// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/olareg/olareg"
	olaregconfig "github.com/olareg/olareg/config"
	"github.com/policylabs/attestation"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	cenvelope "github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/envelope/dsse"
)

func startTestRegistry(t *testing.T) string {
	t.Helper()
	srv := olareg.New(olaregconfig.Config{
		Storage: olaregconfig.ConfigStorage{
			StoreType: olaregconfig.StoreMem,
		},
	})
	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		ts.Close()
		if err := srv.Close(); err != nil {
			t.Logf("closing olareg: %v", err)
		}
	})
	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)
	return tsURL.Host
}

// pushEmptySubject pushes a minimal empty image to ref so the registry has a
// subject for the .att tag to point at, and returns its digest in
// `sha256:<hex>` form.
func pushEmptySubject(t *testing.T, ctx context.Context, ref string) string {
	t.Helper()
	require.NoError(t, crane.Push(empty.Image, ref, crane.WithContext(ctx), crane.Insecure))
	d, err := crane.Digest(ref, crane.WithContext(ctx), crane.Insecure)
	require.NoError(t, err)
	return d
}

// validIntotoPayload builds a tiny valid in-toto statement so the round-trip
// fetch path can produce a non-nil Statement.
func validIntotoPayload() []byte {
	return []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://example.com/test/v1","subject":[{"name":"x","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicate":{}}`)
}

func makeDSSEEnvelope() *dsse.Envelope {
	return &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     validIntotoPayload(),
			Signatures: []*protodsse.Signature{
				{Keyid: "k", Sig: []byte("sig")},
			},
		},
	}
}

func TestStoreRoundTripPlainDSSE(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/dsse:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	env := makeDSSEEnvelope()
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{env}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.NotNil(t, atts[0].GetStatement())
}

func TestFetchAttestationLayersDisabled(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/att-off:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))

	off, err := New(WithReference(repo), WithCraneOpts(crane.Insecure), WithReadAttestations(false))
	require.NoError(t, err)

	atts, err := off.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestStoreAppendsToExistingAttestationImage(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/append:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	// First write.
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))
	// Second write — must preserve the first and append the second.
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 2, "appending should preserve prior layers")
}

func TestStoreRoundTripBundleWithCosignAnnotations(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/bundle:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	mt, err := sbundle.MediaTypeString("v0.3")
	require.NoError(t, err)

	// Build a bundle envelope with sigstore verification material so the
	// storer must hoist it into cosign layer annotations and the fetcher must
	// re-parse it back into a bundle on read.
	fakeCert := []byte{0x30, 0x82, 0x01, 0x0a} // not a real cert; only used to round-trip RawBytes
	logIDBytes := []byte{0xab, 0xcd, 0xef}
	setBytes := []byte("signed-entry-timestamp")
	canonicalBody := []byte(`{"kind":"hashedrekord","apiVersion":"0.0.1"}`)
	tsDER := []byte("rfc3161-der-bytes")

	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType: mt,
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     validIntotoPayload(),
					Signatures: []*protodsse.Signature{
						{Keyid: "k", Sig: []byte("sig")},
					},
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{{RawBytes: fakeCert}},
					},
				},
				TlogEntries: []*protorekor.TransparencyLogEntry{{
					LogIndex:          42,
					LogId:             &protocommon.LogId{KeyId: logIDBytes},
					IntegratedTime:    1700000000,
					InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: setBytes},
					CanonicalizedBody: canonicalBody,
				}},
				TimestampVerificationData: &protobundle.TimestampVerificationData{
					Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
						{SignedTimestamp: tsDER},
					},
				},
			},
		},
	}

	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{bun}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)

	got, ok := atts[0].(*bundle.Envelope)
	require.True(t, ok, "fetched envelope should be a bundle.Envelope since cosign annotations were preserved")

	// Cert chain round-tripped.
	chain := got.Bundle.GetVerificationMaterial().GetX509CertificateChain()
	require.NotNil(t, chain)
	require.Len(t, chain.GetCertificates(), 1)
	require.Equal(t, fakeCert, chain.GetCertificates()[0].GetRawBytes())

	// Tlog entry round-tripped — the fetch path repopulates LogIndex,
	// IntegratedTime, LogId, SignedEntryTimestamp, and CanonicalizedBody.
	tlogs := got.Bundle.GetVerificationMaterial().GetTlogEntries()
	require.Len(t, tlogs, 1)
	require.EqualValues(t, 42, tlogs[0].GetLogIndex())
	require.EqualValues(t, 1700000000, tlogs[0].GetIntegratedTime())
	require.Equal(t, logIDBytes, tlogs[0].GetLogId().GetKeyId())
	require.Equal(t, setBytes, tlogs[0].GetInclusionPromise().GetSignedEntryTimestamp())
	require.Equal(t, canonicalBody, tlogs[0].GetCanonicalizedBody())

	// RFC3161 timestamp round-tripped.
	ts := got.Bundle.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()
	require.Len(t, ts, 1)
	require.Equal(t, tsDER, ts[0].GetSignedTimestamp())

	// Nothing is kept unless asked
	require.Nil(t, cenvelope.OriginContent(got.GetPredicate()))

	// The bundle is put together from the layer and its annotations, so
	// what is kept is the bundle as it serializes. It reads back through
	// the bundle parser with the verification material it had.
	atts, err = c.Fetch(ctx, attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	content := requireKeptContent(t, atts[0])

	rd, ok := atts[0].GetPredicate().GetOrigin().(*gointoto.ResourceDescriptor)
	require.True(t, ok)
	require.Equal(t, mt, rd.GetMediaType())
	require.True(t, strings.HasPrefix(rd.GetUri(), "oci:"), rd.GetUri())

	parser := cenvelope.Parsers.ForMediaType(rd.GetMediaType())
	require.IsType(t, &bundle.Parser{}, parser)
	again, err := parser.ParseStream(bytes.NewReader(content))
	require.NoError(t, err)
	require.Len(t, again, 1)
	back, ok := again[0].(*bundle.Envelope)
	require.True(t, ok)
	fetched, ok := atts[0].(*bundle.Envelope)
	require.True(t, ok)
	require.True(t, proto.Equal(&fetched.Bundle, &back.Bundle), "the bundle read back differs from the one fetched")
	require.Equal(t, atts[0].GetPredicate().GetType(), back.GetPredicate().GetType())
}

// A layer without verification material is the attestation itself, a DSSE
// envelope, and is kept as it was read from the registry.
func TestFetchKeepContentPlainDSSE(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/dsse-content:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope()}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.Nil(t, cenvelope.OriginContent(atts[0].GetPredicate()), "content is not kept unless asked")

	atts, err = c.Fetch(ctx, attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	content := requireKeptContent(t, atts[0])

	rd, ok := atts[0].GetPredicate().GetOrigin().(*gointoto.ResourceDescriptor)
	require.True(t, ok)
	require.Equal(t, dsse.MediaType, rd.GetMediaType())

	again, err := cenvelope.Parsers.ForMediaType(rd.GetMediaType()).ParseStream(bytes.NewReader(content))
	require.NoError(t, err)
	require.Len(t, again, 1)
	require.Equal(t, atts[0].GetPredicate().GetType(), again[0].GetPredicate().GetType())
	require.JSONEq(t, string(atts[0].GetPredicate().GetData()), string(again[0].GetPredicate().GetData()))
	require.Len(t, again[0].GetSignatures(), 1)
}

// layerAnnotations returns the annotations of every layer in the .att manifest
// hanging off ref, in layer order.
func layerAnnotations(t *testing.T, ctx context.Context, ref, digest string) []map[string]string {
	t.Helper()
	info, err := parseImageReference(ctx, ref, crane.Insecure)
	require.NoError(t, err)
	attTag := fmt.Sprintf("%s/%s:%s.att", info.Registry, info.Repository, strings.Replace(digest, "sha256:", "sha256-", 1))
	raw, err := crane.Manifest(attTag, crane.WithContext(ctx), crane.Insecure)
	require.NoError(t, err)
	var manifest struct {
		Layers []struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"layers"`
	}
	require.NoError(t, json.Unmarshal(raw, &manifest))
	ret := make([]map[string]string, 0, len(manifest.Layers))
	for _, l := range manifest.Layers {
		ret = append(ret, l.Annotations)
	}
	return ret
}

func TestStoreWritesPredicateTypeAnnotation(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/predicatetype:v1", host)
	digest := pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	// One plain DSSE envelope built in memory and one bundle envelope, the
	// two shapes Store unwraps. Both carry validIntotoPayload().
	mt, err := sbundle.MediaTypeString("v0.3")
	require.NoError(t, err)
	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType: mt,
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     validIntotoPayload(),
					Signatures:  []*protodsse.Signature{{Keyid: "k", Sig: []byte("sig")}},
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{{RawBytes: []byte{0x30, 0x82, 0x01, 0x0a}}},
					},
				},
			},
		},
	}
	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{makeDSSEEnvelope(), bun}))

	layers := layerAnnotations(t, ctx, repo, digest)
	require.Len(t, layers, 2)
	for i, ann := range layers {
		require.Equal(t, "https://example.com/test/v1", ann[predicateTypeAnnotation], "layer %d", i)
	}
	// The cosign annotations are still hoisted next to it on the bundle layer.
	require.Contains(t, layers[1], "dev.sigstore.cosign/certificate")
}

func TestPredicateTypeForLayer(t *testing.T) {
	t.Parallel()
	// Envelope with a statement: read from the parsed statement or the payload
	env := makeDSSEEnvelope()
	layerBytes, _, err := dsseLayerForEnvelope(env)
	require.NoError(t, err)
	require.Equal(t, "https://example.com/test/v1", predicateTypeForLayer(env, layerBytes))

	// Payload that is not an in-toto statement yields no annotation
	plain := &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "text/plain",
			Payload:     []byte("not a statement"),
			Signatures:  []*protodsse.Signature{{Keyid: "k", Sig: []byte("sig")}},
		},
	}
	layerBytes, _, err = dsseLayerForEnvelope(plain)
	require.NoError(t, err)
	require.Empty(t, predicateTypeForLayer(plain, layerBytes))

	// Garbage layer bytes never panic
	require.Empty(t, predicateTypeForLayer(plain, []byte("{")))
}

// TestFetchSkipsUnparseableStatement stores an attestation whose payload is
// not a valid in-toto statement (its predicate is a JSON string, as some
// older cosign SBOM attestations have) next to a valid one and checks that
// Fetch skips it instead of failing or panicking, with or without cosign
// verification material on the layer.
func TestFetchSkipsUnparseableStatement(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/unparseable:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	badPayload := []byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://spdx.dev/Document","subject":[{"name":"x","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicate":"{\"SPDXID\":\"SPDXRef-DOCUMENT\"}"}`)

	// Plain DSSE layer (no verification material)
	plain := &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     badPayload,
			Signatures:  []*protodsse.Signature{{Keyid: "k", Sig: []byte("sig")}},
		},
	}

	// Bundle layer, stored with the certificate annotation so the fetch
	// path rebuilds a bundle from it
	mt, err := sbundle.MediaTypeString("v0.3")
	require.NoError(t, err)
	withCert := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType: mt,
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "application/vnd.in-toto+json",
					Payload:     badPayload,
					Signatures:  []*protodsse.Signature{{Keyid: "k", Sig: []byte("sig")}},
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_X509CertificateChain{
					X509CertificateChain: &protocommon.X509CertificateChain{
						Certificates: []*protocommon.X509Certificate{{RawBytes: []byte{0x30, 0x82, 0x01, 0x0a}}},
					},
				},
			},
		},
	}

	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, []attestation.Envelope{plain, withCert, makeDSSEEnvelope()}))

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1, "only the valid statement should be returned")
	require.NotNil(t, atts[0].GetStatement())
	require.Equal(t, attestation.PredicateType("https://example.com/test/v1"), atts[0].GetStatement().GetPredicateType())
}

func TestStoreEmptyEnvelopesIsNoop(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/empty:v1", host)
	pushEmptySubject(t, ctx, repo)

	c, err := New(WithReference(repo), WithCraneOpts(crane.Insecure))
	require.NoError(t, err)

	require.NoError(t, c.Store(ctx, attestation.StoreOptions{}, nil))
}

func TestCosignAnnotationsFromMaterialNil(t *testing.T) {
	t.Parallel()
	ann, err := cosignAnnotationsFromMaterial(nil)
	require.NoError(t, err)
	require.Nil(t, ann)
}

func TestCosignAnnotationsFromMaterialShapes(t *testing.T) {
	t.Parallel()
	logID := []byte{0x01, 0x02}
	mat := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: []byte("cert")}},
			},
		},
		TlogEntries: []*protorekor.TransparencyLogEntry{{
			LogIndex:          7,
			LogId:             &protocommon.LogId{KeyId: logID},
			IntegratedTime:    12345,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: []byte("set")},
			CanonicalizedBody: []byte("body"),
		}},
		TimestampVerificationData: &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
				{SignedTimestamp: []byte("ts")},
			},
		},
	}

	ann, err := cosignAnnotationsFromMaterial(mat)
	require.NoError(t, err)

	// Certificate is PEM-encoded.
	certPEM := ann["dev.sigstore.cosign/certificate"]
	require.NotEmpty(t, certPEM)
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block)
	require.Equal(t, "CERTIFICATE", block.Type)
	require.Equal(t, []byte("cert"), block.Bytes)

	// Bundle annotation has the right shape.
	bundleJSON := ann["dev.sigstore.cosign/bundle"]
	require.NotEmpty(t, bundleJSON)
	var b struct {
		Payload struct {
			Body           string `json:"body"`
			IntegratedTime int64  `json:"integratedTime"`
			LogIndex       int64  `json:"logIndex"`
			LogID          string `json:"logID"`
		} `json:"Payload"`
		SignedEntryTimestamp string `json:"SignedEntryTimestamp"`
	}
	require.NoError(t, json.Unmarshal([]byte(bundleJSON), &b))
	require.EqualValues(t, 7, b.Payload.LogIndex)
	require.EqualValues(t, 12345, b.Payload.IntegratedTime)
	require.Equal(t, hex.EncodeToString(logID), b.Payload.LogID)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("body")), b.Payload.Body)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("set")), b.SignedEntryTimestamp)

	// Timestamp annotation has the right shape.
	tsJSON := ann["dev.sigstore.cosign/rfc3161timestamp"]
	require.NotEmpty(t, tsJSON)
	var ts struct {
		SignedRFC3161Timestamp string `json:"SignedRFC3161Timestamp"`
	}
	require.NoError(t, json.Unmarshal([]byte(tsJSON), &ts))
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("ts")), ts.SignedRFC3161Timestamp)
}

func TestDSSELayerForEnvelopeBundle(t *testing.T) {
	t.Parallel()
	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					PayloadType: "x",
					Payload:     []byte("p"),
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{},
		},
	}
	data, material, err := dsseLayerForEnvelope(bun)
	require.NoError(t, err)
	require.NotNil(t, material)
	require.NotEmpty(t, data)
	require.Contains(t, string(data), `"payloadType"`)
}

func TestDSSELayerForEnvelopeBundleWithoutDSSE(t *testing.T) {
	t.Parallel()
	bun := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			Content: &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{},
			},
		},
	}
	_, _, err := dsseLayerForEnvelope(bun)
	require.Error(t, err)
}

func TestDSSELayerForEnvelopePlainDSSE(t *testing.T) {
	t.Parallel()
	env := &dsse.Envelope{
		Envelope: &protodsse.Envelope{
			PayloadType: "x",
			Payload:     []byte("p"),
		},
	}
	data, material, err := dsseLayerForEnvelope(env)
	require.NoError(t, err)
	require.Nil(t, material)
	require.Contains(t, string(data), `"payloadType"`)
}
