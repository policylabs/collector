// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"encoding/base64"
	"testing"

	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/policylabs/attestation"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/stretchr/testify/require"
)

func TestVerificationMaterialMissingCert(t *testing.T) {
	t.Parallel()
	// Layer with empty cosign annotations should fail gracefully.
	layer := &ggcr.Descriptor{
		Annotations: map[string]string{
			"dev.sigstore.cosign/certificate": "",
			"dev.sigstore.cosign/chain":       "",
			"dev.sigstore.cosign/signature":   "",
		},
	}
	_, err := verificationMaterialFromOCILayer(layer)
	require.Error(t, err)
}

func TestVerificationMaterialNoCertAnnotation(t *testing.T) {
	t.Parallel()
	layer := &ggcr.Descriptor{
		Annotations: map[string]string{},
	}
	_, err := verificationMaterialFromOCILayer(layer)
	require.Error(t, err)
}

func TestBuildPlainDSSEEnvelope(t *testing.T) {
	t.Parallel()
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v0.2","predicate":{}}`)

	dsseEnv := &protobundle.Bundle_DsseEnvelope{
		DsseEnvelope: &protodsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     payload,
			Signatures: []*protodsse.Signature{
				{
					Keyid: "test-key",
					Sig:   []byte(base64.StdEncoding.EncodeToString([]byte("fake-sig"))),
				},
			},
		},
	}

	env, err := buildPlainDSSEEnvelope(dsseEnv, "oci:example.com/repo:sha256-abc.att", nil)
	require.NoError(t, err)
	require.NotNil(t, env)
	require.NotNil(t, env.GetStatement())
	require.NotNil(t, env.GetPredicate())
	require.Equal(t, attestation.PredicateType("https://slsa.dev/provenance/v0.2"), env.GetPredicate().GetType())
	require.Len(t, env.GetSignatures(), 1)
}

func TestFetch(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name         string
		ref          string
		expectedAtts int
	}{
		{"chainguard", "cgr.dev/chainguard/go", 4},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithReference(tt.ref))
			require.NoError(t, err)

			atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tt.expectedAtts)
		})
	}
}

func TestReadOptionsDefaultOn(t *testing.T) {
	t.Parallel()
	c, err := New(WithReference("example.com/repo:v1"))
	require.NoError(t, err)
	require.True(t, c.Options.ReadAttestations)
	require.True(t, c.Options.ReadSignatures)
	require.True(t, c.Options.ReadSBOMs)

	c, err = New(
		WithReference("example.com/repo:v1"),
		WithReadAttestations(false), WithReadSignatures(false), WithReadSBOMs(false),
	)
	require.NoError(t, err)
	require.False(t, c.Options.ReadAttestations)
	require.False(t, c.Options.ReadSignatures)
	require.False(t, c.Options.ReadSBOMs)
}
