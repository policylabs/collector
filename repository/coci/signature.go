// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/crane"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/internal/readlimit"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/statement/intoto"
)

// CosignSignaturePredicateType is the predicate type for virtual attestations
// synthesized from cosign .sig image layers.
const CosignSignaturePredicateType = attestation.PredicateType("https://cosign.sigstore.dev/signature/v1")

// cosignSimpleSigningMediaType is the media type used by cosign signature layers.
const cosignSimpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

// fetchSignatures fetches the cosign .sig image for the given image and returns
// synthetic attestation envelopes for each verified signature layer.
func (c *Collector) fetchSignatures(ctx context.Context, opts attestation.FetchOptions, imageInfo *ImageInfo) ([]attestation.Envelope, error) {
	sigRef := fmt.Sprintf(
		"%s/%s:%s.sig",
		imageInfo.Registry, imageInfo.Repository,
		strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
	)

	manifestData, err := crane.Manifest(sigRef, append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)...)
	if err != nil {
		return nil, fmt.Errorf("fetching .sig manifest: %w", err)
	}

	manifest, err := ggcr.ParseManifest(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parsing .sig manifest: %w", err)
	}

	// Identify signature layers.
	type indexedLayer struct {
		index int
		layer *ggcr.Descriptor
	}
	var sigLayers []indexedLayer
	for i := range manifest.Layers {
		if string(manifest.Layers[i].MediaType) == cosignSimpleSigningMediaType {
			sigLayers = append(sigLayers, indexedLayer{i, &manifest.Layers[i]})
		}
	}

	// Pull signature layers in parallel (up to 10 concurrent).
	type layerResult struct {
		envelope attestation.Envelope
		err      error
		index    int
	}
	results := make([]layerResult, len(sigLayers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for j, sl := range sigLayers {
		wg.Add(1)
		go func(j int, sl indexedLayer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			env, err := c.getSignatureEnvelope(ctx, &opts, imageInfo, sl.layer)
			results[j] = layerResult{env, err, sl.index}
		}(j, sl)
	}
	wg.Wait()

	// Collect results preserving layer order. Errors are non-fatal per layer.
	var atts []attestation.Envelope
	for _, r := range results {
		if r.err != nil {
			logrus.Debugf("coci: skipping .sig layer %d: %v", r.index, r.err)
			continue
		}
		atts = append(atts, r.envelope)
		if opts.Limit > 0 && len(atts) >= opts.Limit {
			break
		}
	}

	return atts, nil
}

// getSignatureEnvelope reads a single cosign signature layer and returns a
// synthetic attestation envelope after verifying the signature.
func (c *Collector) getSignatureEnvelope(ctx context.Context, opts *attestation.FetchOptions, imageInfo *ImageInfo, layer *ggcr.Descriptor) (attestation.Envelope, error) {
	// Pull the layer blob (simple signing payload)
	layerRef := imageInfo.Registry + "/" + imageInfo.Repository + "@" + layer.Digest.String()
	pulled, err := crane.PullLayer(layerRef, append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)...)
	if err != nil {
		return nil, fmt.Errorf("pulling signature layer: %w", err)
	}

	blob, err := pulled.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("reading signature blob: %w", err)
	}
	defer blob.Close() //nolint:errcheck

	payload, err := io.ReadAll(readlimit.Reader(blob, opts.MaxReadSize))
	if err != nil {
		return nil, fmt.Errorf("reading signature payload: %w", err)
	}

	env, err := c.signatureEnvelope(imageInfo, layer, payload)
	if err != nil {
		return nil, err
	}
	if opts.KeepContent {
		if err := keepSignature(env, imageInfo, layer, payload); err != nil {
			return nil, fmt.Errorf("keeping signature payload: %w", err)
		}
	}
	return env, nil
}

// signatureEnvelope builds the attestation of a cosign signature from the
// payload of its layer and from the signature and the material to verify it,
// which the layer carries in its annotations.
func (c *Collector) signatureEnvelope(imageInfo *ImageInfo, layer *ggcr.Descriptor, payload []byte) (attestation.Envelope, error) {
	// Read the base64-encoded signature from the annotation
	sigB64, ok := layer.Annotations["dev.cosignproject.cosign/signature"]
	if !ok {
		return nil, fmt.Errorf("no cosign signature annotation in layer")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decoding cosign signature: %w", err)
	}

	// The MessageDigest in the bundle must be the hash of the simple signing
	// payload — this is what cosign signed and what rekor recorded in the
	// hashedrekord tlog entry. Using the image manifest digest here would
	// cause sigstore-go to fail tlog entry reconciliation.
	payloadDigest := sha256.Sum256(payload)

	// Try sigstore path first: if the layer has verification material,
	// construct a bundle.Envelope with the MessageSignature content and
	// verification material — the same shape as the .att path. Verification
	// is deferred to the downstream Verify() call on the envelope.
	material, err := verificationMaterialFromOCILayer(layer)
	if err == nil {
		return buildSignatureBundleEnvelope(imageInfo, material, signatureBytes, payloadDigest[:], payload, nil)
	}

	// Try extracting the public key from the rekor hashedrekord bundle.
	// This handles images signed with `cosign sign --key` (e.g. Red Hat UBI)
	// where no Fulcio certificate is present but the key is in the tlog entry.
	if env, rekorErr := verifyWithRekorKey(layer, imageInfo, payload, signatureBytes, payloadDigest[:]); rekorErr == nil {
		return env, nil
	} else {
		logrus.Debugf("coci: rekor key verification: %v", rekorErr)
	}

	// Fall back to key-based verification when no sigstore material
	if len(c.Keys) > 0 {
		verification, verErr := c.verifyWithKeys(payload, signatureBytes)
		if verErr != nil {
			return nil, fmt.Errorf("key-based verification failed: %w", verErr)
		}
		return buildSignatureVirtualAttestation(imageInfo, payload, verification)
	}

	return nil, fmt.Errorf("no verification method available for signature layer")
}

// buildSignatureBundleEnvelope constructs a bundle.Envelope with the
// MessageSignature content and verification material from the .sig layer.
// This produces the same envelope shape as the .att path so that
// downstream Verify() works uniformly. The payloadDigest must be the
// SHA-256 hash of the simple signing payload (the artifact that was
// signed and recorded in rekor). When verification is non-nil, it is
// pre-set on the predicate so that Verify() short-circuits.
func buildSignatureBundleEnvelope(imageInfo *ImageInfo, material *protobundle.VerificationMaterial, signatureBytes, payloadDigest, payload []byte, verification *sapi.Verification) (attestation.Envelope, error) {
	mt, err := sbundle.MediaTypeString("v0.3")
	if err != nil {
		return nil, err
	}

	// Build the synthetic statement that the envelope will serve
	rd, err := imageSubject(imageInfo)
	if err != nil {
		return nil, err
	}

	pred := &generic.Predicate{
		Type: CosignSignaturePredicateType,
		Data: payload,
	}

	// Only set Verification when non-nil to avoid the Go nil interface
	// gotcha: a typed nil *sapi.Verification assigned to the
	// attestation.Verification interface field produces a non-nil
	// interface, which would cause bundle.Envelope.Verify() to
	// short-circuit without actually performing sigstore verification.
	if verification != nil {
		pred.Verification = verification
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType:            mt,
			VerificationMaterial: material,
			Content: &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{
					MessageDigest: &protocommon.HashOutput{
						Algorithm: protocommon.HashAlgorithm_SHA2_256,
						Digest:    payloadDigest,
					},
					Signature: signatureBytes,
				},
			},
		},
		Statement: stmt,
	}, nil
}

// verifyWithRekorKey attempts to extract a public key from the rekor
// hashedrekord bundle annotation, verify the signature, and return a
// bundle.Envelope with the verification pre-set.
func verifyWithRekorKey(layer *ggcr.Descriptor, imageInfo *ImageInfo, payload, signatureBytes, payloadDigest []byte) (attestation.Envelope, error) {
	pub, err := extractKeyFromRekorBundle(layer)
	if err != nil {
		return nil, err
	}

	verifier := key.NewVerifier()
	verified, verErr := verifier.VerifyMessage(pub, payload, signatureBytes)
	if verErr != nil {
		return nil, fmt.Errorf("rekor key verification failed: %w", verErr)
	}
	if !verified {
		return nil, fmt.Errorf("rekor key did not verify signature")
	}

	verification := &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:     timestamppb.Now(),
			Verified: true,
			Identities: []*sapi.Identity{
				{
					Key: &sapi.IdentityKey{
						Id:   pub.ID(),
						Type: string(pub.Scheme),
						Data: pub.Data,
					},
				},
			},
		},
	}

	tlogEntries, tlogErr := getVerificationMaterialTlogEntries(layer)
	if tlogErr != nil {
		logrus.Debugf("coci: failed to get tlog entries from rekor bundle: %v", tlogErr)
	}
	timestampEntries, tsErr := getVerificationMaterialTimestampEntries(layer)
	if tsErr != nil {
		logrus.Debugf("coci: failed to get timestamp entries from rekor bundle: %v", tsErr)
	}

	rekorMaterial := &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: pub.ID(),
			},
		},
		TlogEntries:               tlogEntries,
		TimestampVerificationData: timestampEntries,
	}

	return buildSignatureBundleEnvelope(imageInfo, rekorMaterial, signatureBytes, payloadDigest, payload, verification)
}

// extractKeyFromRekorBundle extracts a public key from the hashedrekord entry
// stored in the dev.sigstore.cosign/bundle annotation. This handles images
// signed with `cosign sign --key` where the public key is embedded in the
// Rekor transparency log entry rather than in a Fulcio certificate.
func extractKeyFromRekorBundle(layer *ggcr.Descriptor) (*key.Public, error) {
	bundleJSON, ok := layer.Annotations["dev.sigstore.cosign/bundle"]
	if !ok {
		return nil, fmt.Errorf("no bundle annotation in layer")
	}

	var bundleData struct {
		Payload struct {
			Body string `json:"body"`
		} `json:"Payload"`
	}
	if err := json.Unmarshal([]byte(bundleJSON), &bundleData); err != nil {
		return nil, fmt.Errorf("parsing bundle JSON: %w", err)
	}

	if bundleData.Payload.Body == "" {
		return nil, fmt.Errorf("empty body in bundle payload")
	}

	bodyBytes, err := base64.StdEncoding.DecodeString(bundleData.Payload.Body)
	if err != nil {
		return nil, fmt.Errorf("decoding bundle body: %w", err)
	}

	var body struct {
		Spec struct {
			Signature struct {
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return nil, fmt.Errorf("parsing hashedrekord body: %w", err)
	}

	pemB64 := body.Spec.Signature.PublicKey.Content
	if pemB64 == "" {
		return nil, fmt.Errorf("no public key in hashedrekord")
	}

	pemBytes, err := base64.StdEncoding.DecodeString(pemB64)
	if err != nil {
		return nil, fmt.Errorf("decoding public key base64: %w", err)
	}

	pub, err := key.NewParser().ParsePublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key PEM: %w", err)
	}

	return pub, nil
}

// verifyWithKeys attempts to verify the signature against the payload using
// the collector's configured keys.
func (c *Collector) verifyWithKeys(payload, sigData []byte) (*sapi.Verification, error) {
	if len(c.Keys) == 0 {
		return nil, fmt.Errorf("no keys configured for verification")
	}

	verifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range c.Keys {
		verified, err := verifier.VerifyMessage(pkp, payload, sigData)
		if err != nil {
			logrus.Debugf("key verification error: %v", err)
			continue
		}
		if !verified {
			continue
		}

		pub, err := pkp.PublicKey()
		if err != nil {
			continue
		}

		identities = append(identities, &sapi.Identity{
			Key: &sapi.IdentityKey{
				Id:   pub.ID(),
				Type: string(pub.Scheme),
				Data: pub.Data,
			},
		})
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no key verified the signature")
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   true,
			Identities: identities,
		},
	}, nil
}

// buildSignatureVirtualAttestation creates a virtual attestation for a verified
// cosign signature layer.
func buildSignatureVirtualAttestation(imageInfo *ImageInfo, payload []byte, verification *sapi.Verification) (attestation.Envelope, error) {
	rd, err := imageSubject(imageInfo)
	if err != nil {
		return nil, err
	}

	pred := &generic.Predicate{
		Type:         CosignSignaturePredicateType,
		Data:         payload,
		Verification: verification,
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &virtualEnvelope{statement: stmt}, nil
}

// virtualEnvelope implements attestation.Envelope for virtual signature
// attestations synthesized from cosign .sig layers.
type virtualEnvelope struct {
	statement attestation.Statement
}

var _ attestation.Envelope = (*virtualEnvelope)(nil)

func (e *virtualEnvelope) GetStatement() attestation.Statement {
	return e.statement
}

func (e *virtualEnvelope) GetPredicate() attestation.Predicate {
	if s := e.GetStatement(); s != nil {
		return s.GetPredicate()
	}
	return nil
}

func (e *virtualEnvelope) GetVerification() attestation.Verification {
	if s := e.GetStatement(); s != nil {
		return s.GetVerification()
	}
	return nil
}

func (e *virtualEnvelope) GetSignatures() []attestation.Signature {
	return nil
}

func (e *virtualEnvelope) GetCertificate() attestation.Certificate {
	return nil
}

func (e *virtualEnvelope) Verify(_ ...any) error {
	return nil
}
