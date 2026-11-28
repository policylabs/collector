// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"
)

// fixtureBundleMediaType is the media type bundle-provenance.json declares.
const fixtureBundleMediaType = "application/vnd.dev.sigstore.bundle+json;version=0.1"

func TestKeepContent(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("bundle/testdata/bundle-provenance.json")
	require.NoError(t, err)

	t.Run("kept-with-matching-digest", func(t *testing.T) {
		t.Parallel()
		envs, err := Parsers.Parse(bytes.NewReader(data))
		require.NoError(t, err)
		require.Len(t, envs, 1)
		require.Nil(t, OriginContent(envs[0].GetPredicate()), "content is not kept unless asked")

		KeepContent(envs, data)
		content := OriginContent(envs[0].GetPredicate())
		require.Equal(t, data, content)
		// A bundle records the media type it declares, here an old format
		require.Equal(t, fixtureBundleMediaType, originMediaType(t, envs[0]))

		// The origin's digest is the digest of what was kept
		sum := sha256.Sum256(content)
		require.Equal(t,
			hex.EncodeToString(sum[:]),
			envs[0].GetPredicate().GetOrigin().GetDigest()["sha256"],
		)
	})

	t.Run("more-than-one-envelope", func(t *testing.T) {
		t.Parallel()
		one, err := Parsers.Parse(bytes.NewReader(data))
		require.NoError(t, err)
		two, err := Parsers.Parse(bytes.NewReader(data))
		require.NoError(t, err)
		envs := append(one, two...) //nolint:gocritic // the list under test
		KeepContent(envs, data)
		require.Nil(t, OriginContent(envs[0].GetPredicate()))
		require.Nil(t, OriginContent(envs[1].GetPredicate()))
	})

	t.Run("nothing-to-keep", func(t *testing.T) {
		t.Parallel()
		envs, err := Parsers.Parse(bytes.NewReader(data))
		require.NoError(t, err)
		KeepContent(envs, nil)
		require.Nil(t, OriginContent(envs[0].GetPredicate()))
		KeepContent(nil, data)
		require.Nil(t, OriginContent(nil))
	})
}

func TestJsonlKeepContent(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("../repository/jsonl/testdata/multiple.jsonl")
	require.NoError(t, err)

	envs, err := NewJSONL().Parse(data)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	for _, env := range envs {
		require.Nil(t, OriginContent(env.GetPredicate()))
	}

	envs, err = (&JsonlParser{KeepContent: true}).Parse(data)
	require.NoError(t, err)
	require.Greater(t, len(envs), 1)
	for _, env := range envs {
		content := OriginContent(env.GetPredicate())
		require.NotEmpty(t, content)
		// Each attestation keeps its own line, not the whole file
		require.Less(t, len(content), len(data))
		sum := sha256.Sum256(content)
		require.Equal(t, hex.EncodeToString(sum[:]), env.GetPredicate().GetOrigin().GetDigest()["sha256"])
	}
}

// originMediaType returns the media type recorded in the origin of an
// attestation.
func originMediaType(t *testing.T, env attestation.Envelope) string {
	t.Helper()
	rd, ok := env.GetPredicate().GetOrigin().(*intoto.ResourceDescriptor)
	require.True(t, ok)
	return rd.GetMediaType()
}

func TestKeepContentMediaType(t *testing.T) {
	t.Parallel()
	bundleData, err := os.ReadFile("bundle/testdata/bundle-provenance.json")
	require.NoError(t, err)
	statementData, err := os.ReadFile("../repository/filesystem/testdata/results.intoto.json")
	require.NoError(t, err)

	for _, tc := range []struct {
		name        string
		data        []byte
		mediaType   string
		attestation bool
	}{
		{"bundle", bundleData, fixtureBundleMediaType, true},
		{
			"dsse",
			[]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` +
				base64.StdEncoding.EncodeToString(statementData) +
				`","signatures":[{"keyid":"","sig":"c2ln"}]}`),
			MediaTypeDSSE, true,
		},
		{"statement", statementData, MediaTypeInToto, true},
		// Not an attestation: the parser wraps the data in a statement, so
		// reading the content back means doing that again.
		{"predicate", []byte(`{"some":"report"}`), MediaTypeJSON, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			envs, err := Parsers.Parse(bytes.NewReader(tc.data))
			require.NoError(t, err)
			require.Len(t, envs, 1)

			KeepContent(envs, tc.data)
			require.Equal(t, tc.data, OriginContent(envs[0].GetPredicate()))
			mediaType := originMediaType(t, envs[0])
			require.Equal(t, tc.mediaType, mediaType)
			require.Equal(t, tc.attestation, IsAttestationMediaType(mediaType))
		})
	}
}

func TestIsAttestationMediaType(t *testing.T) {
	t.Parallel()
	for mediaType, expect := range map[string]bool{
		"application/vnd.dev.sigstore.bundle.v0.3+json":        true,
		"application/vnd.dev.sigstore.bundle+json;version=0.1": true,
		MediaTypeDSSE:    true,
		MediaTypeInToto:  true,
		MediaTypeJSON:    false,
		"text/spdx+json": false,
		"":               false,
	} {
		require.Equal(t, expect, IsAttestationMediaType(mediaType), mediaType)
	}
}
