// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	cenvelope "github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
)

// Keys of the reassembly material recorded with a kept signature payload:
// what the attestation is built from that the payload does not hold.
const (
	// materialLayer says which kind of layer the content was read from.
	// Signature layers are the only ones that need reassembling: what is
	// kept for attestation and SBOM layers reads back through a parser.
	materialLayer          = "layer"
	materialLayerSignature = "signature"

	// materialAnnotations holds the annotations of the layer, where cosign
	// puts the signature and what verifies it (certificate, transparency
	// log entry, timestamp).
	materialAnnotations = "annotations"

	// materialRepository and materialDigest identify the image that was
	// signed, the subject of the attestation; materialRegistry its registry.
	materialRegistry   = "registry"
	materialRepository = "repository"
	materialDigest     = "digest"
)

// keepSignature records the payload of a cosign signature layer as the origin
// of the attestation synthesized from it.
//
// The content is the payload as read from the registry, the simple signing
// document cosign signed, typed as the layer is. That is not an attestation
// and no envelope parser reads it, so the origin names this repository type,
// with the annotations of the layer and the image that was signed, and
// Reassemble builds the attestation again from them.
func keepSignature(env attestation.Envelope, imageInfo *ImageInfo, layer *ggcr.Descriptor, payload []byte) error {
	if err := cenvelope.KeepData(env, payload, cosignSimpleSigningMediaType); err != nil {
		return err
	}
	origin, ok := env.GetPredicate().GetOrigin().(*gointoto.ResourceDescriptor)
	if !ok || origin == nil {
		return errors.New("attestation has no origin to annotate")
	}
	origin.Uri = fmt.Sprintf("oci:%s/%s@%s", imageInfo.Registry, imageInfo.Repository, layer.Digest.String())

	annotations := make(map[string]any, len(layer.Annotations))
	for k, v := range layer.Annotations {
		annotations[k] = v
	}
	return repository.Annotate(origin, TypeMoniker, map[string]any{
		materialLayer:       materialLayerSignature,
		materialAnnotations: annotations,
		materialRegistry:    imageInfo.Registry,
		materialRepository:  imageInfo.Repository,
		materialDigest:      imageInfo.Digest,
	})
}

// Reassemble rebuilds the attestation kept in an origin by this repository
// type: the one synthesized from a cosign signature layer. The payload is
// read from the content and the signature and its verification material
// from the layer annotations recorded with it, and the attestation is built
// from them as it was the first time.
//
// A signature that verifies with sigstore material comes back to be
// verified, as when first read. One that only verified against a configured
// key cannot be rebuilt: no keys can be configured here.
func Reassemble(_ context.Context, origin *gointoto.ResourceDescriptor) ([]attestation.Envelope, error) {
	material := repository.Material(origin)
	if material == nil {
		return nil, errors.New("origin has no reassembly material")
	}
	str := func(k string) string {
		s, _ := material[k].(string) //nolint:errcheck // an absent or odd value reads as empty
		return s
	}
	if kind := str(materialLayer); kind != materialLayerSignature {
		return nil, fmt.Errorf("reassembly material is not of a signature layer (%q)", kind)
	}

	payload := origin.GetContent()
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	// The content has to be the payload the origin says it is
	if want := origin.GetDigest()["sha256"]; want != digest {
		return nil, fmt.Errorf("kept payload is sha256:%s, not sha256:%s as its origin says", digest, want)
	}

	layer := &ggcr.Descriptor{
		MediaType:   types.MediaType(cosignSimpleSigningMediaType),
		Size:        int64(len(payload)),
		Digest:      ggcr.Hash{Algorithm: "sha256", Hex: digest},
		Annotations: map[string]string{},
	}
	annotations, _ := material[materialAnnotations].(map[string]any) //nolint:errcheck // absent reads as none
	for k, v := range annotations {
		if s, ok := v.(string); ok {
			layer.Annotations[k] = s
		}
	}

	imageInfo := &ImageInfo{
		Registry:   str(materialRegistry),
		Repository: str(materialRepository),
		Digest:     str(materialDigest),
	}

	env, err := (&Collector{}).signatureEnvelope(imageInfo, layer, payload)
	if err != nil {
		return nil, err
	}
	return []attestation.Envelope{env}, nil
}
