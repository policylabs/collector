// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	cenvelope "github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/repository"
)

const testSignaturePayload = `{"critical":{"identity":{"docker-reference":"example.com/test"},"type":"cosign container image signature"},"optional":null}`

// pushSignatureImage attaches a cosign signature layer to the image with the
// given digest: the simple signing payload, with the signature and sigstore
// verification material in the annotations of the layer. Nothing in it
// verifies; it is shaped as cosign shapes it.
func pushSignatureImage(t *testing.T, ctx context.Context, repo, digest string) {
	t.Helper()
	annotations, err := cosignAnnotationsFromMaterial(&protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: []*protocommon.X509Certificate{{RawBytes: []byte{0x30, 0x82, 0x01, 0x0a}}},
			},
		},
		TlogEntries: []*protorekor.TransparencyLogEntry{{
			LogIndex:          42,
			LogId:             &protocommon.LogId{KeyId: []byte{0xab, 0xcd, 0xef}},
			IntegratedTime:    1700000000,
			InclusionPromise:  &protorekor.InclusionPromise{SignedEntryTimestamp: []byte("signed-entry-timestamp")},
			CanonicalizedBody: []byte(`{"kind":"hashedrekord","apiVersion":"0.0.1"}`),
		}},
	})
	require.NoError(t, err)
	annotations["dev.cosignproject.cosign/signature"] = base64.StdEncoding.EncodeToString([]byte("signature"))

	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       static.NewLayer([]byte(testSignaturePayload), types.MediaType(cosignSimpleSigningMediaType)),
		Annotations: annotations,
	})
	require.NoError(t, err)
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, types.OCIConfigJSON)
	tag := fmt.Sprintf("%s:%s.sig", repo, strings.Replace(digest, "sha256:", "sha256-", 1))
	require.NoError(t, crane.Push(img, tag, crane.WithContext(ctx), crane.Insecure))
}

func TestReassembleSignature(t *testing.T) {
	t.Parallel()
	host := startTestRegistry(t)
	ctx := t.Context()

	repo := fmt.Sprintf("%s/test/coci/signature", host)
	digest := pushEmptySubject(t, ctx, repo+":v1")
	pushSignatureImage(t, ctx, repo, digest)

	c, err := New(
		WithReference(repo+":v1"), WithCraneOpts(crane.Insecure),
		WithReadAttestations(false), WithReadSBOMs(false),
	)
	require.NoError(t, err)

	atts, err := c.Fetch(ctx, attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.Equal(t, CosignSignaturePredicateType, atts[0].GetPredicate().GetType())
	require.Nil(t, cenvelope.OriginContent(atts[0].GetPredicate()), "content is not kept unless asked")

	atts, err = c.Fetch(ctx, attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	original, ok := atts[0].(*bundle.Envelope)
	require.True(t, ok)

	// What is kept is the payload cosign signed, as read from the layer
	content := requireKeptContent(t, original)
	require.True(t, bytes.Equal([]byte(testSignaturePayload), content), "kept content differs from the layer")

	// The origin travels serialized, in the results of an evaluation
	kept, ok := original.GetPredicate().GetOrigin().(*gointoto.ResourceDescriptor)
	require.True(t, ok)
	data, err := protojson.Marshal(kept)
	require.NoError(t, err)
	origin := &gointoto.ResourceDescriptor{}
	require.NoError(t, protojson.Unmarshal(data, origin))

	// The payload is not an attestation: no parser reads its type and the
	// origin names this repository type to rebuild it.
	require.Equal(t, cosignSimpleSigningMediaType, origin.GetMediaType())
	require.Nil(t, cenvelope.Parsers.ForMediaType(origin.GetMediaType()))
	require.Equal(t, TypeMoniker, repository.Annotated(origin))
	require.True(t, strings.HasPrefix(origin.GetUri(), "oci:"+repo+"@sha256:"), origin.GetUri())

	rebuilt, err := Reassemble(ctx, origin)
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	env, ok := rebuilt[0].(*bundle.Envelope)
	require.True(t, ok)

	// Same signature and material to verify it, same statement
	require.True(t, proto.Equal(&original.Bundle, &env.Bundle), "the bundle rebuilt differs from the one fetched")
	require.NotNil(t, env.GetMessageSignature())
	require.Equal(t, CosignSignaturePredicateType, env.GetPredicate().GetType())
	require.Equal(t, original.GetPredicate().GetData(), env.GetPredicate().GetData())
	want, got := original.GetStatement().GetSubjects(), env.GetStatement().GetSubjects()
	require.Len(t, got, 1)
	require.Equal(t, want[0].GetName(), got[0].GetName())
	require.Equal(t, want[0].GetDigest(), got[0].GetDigest())
	require.Equal(t, strings.TrimPrefix(digest, "sha256:"), got[0].GetDigest()["sha256"])

	t.Run("tampered-payload", func(t *testing.T) {
		t.Parallel()
		tampered, ok := proto.Clone(origin).(*gointoto.ResourceDescriptor)
		require.True(t, ok)
		tampered.Content = append(tampered.Content, ' ')
		_, err := Reassemble(ctx, tampered)
		require.ErrorContains(t, err, "as its origin says")
	})
	t.Run("no-material", func(t *testing.T) {
		t.Parallel()
		_, err := Reassemble(ctx, &gointoto.ResourceDescriptor{Content: origin.GetContent(), Digest: origin.GetDigest()})
		require.ErrorContains(t, err, "no reassembly material")
	})
	t.Run("not-a-signature-layer", func(t *testing.T) {
		t.Parallel()
		other := &gointoto.ResourceDescriptor{Content: origin.GetContent(), Digest: origin.GetDigest()}
		require.NoError(t, repository.Annotate(other, TypeMoniker, map[string]any{materialLayer: "sbom"}))
		_, err := Reassemble(ctx, other)
		require.ErrorContains(t, err, "not of a signature layer")
	})
	// A signature that only a configured key verified cannot be rebuilt:
	// without its sigstore material there is no way to verify it here.
	t.Run("no-verification-material", func(t *testing.T) {
		t.Parallel()
		other := &gointoto.ResourceDescriptor{Content: origin.GetContent(), Digest: origin.GetDigest()}
		require.NoError(t, repository.Annotate(other, TypeMoniker, map[string]any{
			materialLayer:       materialLayerSignature,
			materialAnnotations: map[string]any{"dev.cosignproject.cosign/signature": "c2ln"},
			materialRepository:  "test", materialDigest: digest,
		}))
		_, err := Reassemble(ctx, other)
		require.ErrorContains(t, err, "no verification method")
	})
}
