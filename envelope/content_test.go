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

	"github.com/policylabs/collector/envelope/bare"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/envelope/dsse"
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
		name      string
		data      []byte
		mediaType string
	}{
		{"bundle", bundleData, fixtureBundleMediaType},
		{
			"dsse",
			[]byte(`{"payloadType":"application/vnd.in-toto+json","payload":"` +
				base64.StdEncoding.EncodeToString(statementData) +
				`","signatures":[{"keyid":"","sig":"c2ln"}]}`),
			dsse.MediaType,
		},
		{"statement", statementData, bare.MediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			envs, err := Parsers.Parse(bytes.NewReader(tc.data))
			require.NoError(t, err)
			require.Len(t, envs, 1)

			// An attestation is kept as it was read
			KeepContent(envs, tc.data)
			require.Equal(t, tc.data, OriginContent(envs[0].GetPredicate()))
			mediaType := originMediaType(t, envs[0])
			require.Equal(t, tc.mediaType, mediaType)

			// ... and the parser of its media type reads it back
			parser := Parsers.ForMediaType(mediaType)
			require.NotNil(t, parser)
			again, err := parser.ParseStream(bytes.NewReader(OriginContent(envs[0].GetPredicate())))
			require.NoError(t, err)
			require.Len(t, again, 1)
			require.Equal(t, envs[0].GetPredicate().GetType(), again[0].GetPredicate().GetType())
			require.JSONEq(t, string(envs[0].GetPredicate().GetData()), string(again[0].GetPredicate().GetData()))
		})
	}
}

// Data that is not an attestation is kept as the statement the parser
// wrapped it in, which reads back as it is.
func TestKeepContentWrappedPredicate(t *testing.T) {
	t.Parallel()
	data := []byte(`{"some":"report","findings":[1,2,3]}`)

	envs, err := Parsers.Parse(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, envs, 1)
	read := envs[0].GetPredicate().GetOrigin().GetDigest()["sha256"]

	KeepContent(envs, data)
	content := OriginContent(envs[0].GetPredicate())
	require.NotEmpty(t, content)
	require.NotEqual(t, data, content)
	require.Equal(t, bare.MediaType, originMediaType(t, envs[0]))

	// The digest of the origin is that of the statement kept, no longer
	// that of the data that was read.
	sum := sha256.Sum256(content)
	kept := envs[0].GetPredicate().GetOrigin().GetDigest()["sha256"]
	require.Equal(t, hex.EncodeToString(sum[:]), kept)
	require.NotEqual(t, read, kept)

	again, err := Parsers.ForMediaType(bare.MediaType).ParseStream(bytes.NewReader(content))
	require.NoError(t, err)
	require.Len(t, again, 1)
	require.Equal(t, envs[0].GetPredicate().GetType(), again[0].GetPredicate().GetType())
	require.JSONEq(t, string(data), string(again[0].GetPredicate().GetData()))
}

func TestForMediaType(t *testing.T) {
	t.Parallel()
	for mediaType, expect := range map[string]any{
		"application/vnd.dev.sigstore.bundle.v0.3+json":        &bundle.Parser{},
		"application/vnd.dev.sigstore.bundle+json;version=0.1": &bundle.Parser{},
		dsse.MediaType:     &dsse.Parser{},
		bare.MediaType:     &bare.Parser{},
		"application/json": nil,
		"text/spdx+json":   nil,
		"":                 nil,
	} {
		parser := Parsers.ForMediaType(mediaType)
		require.Equal(t, expect != nil, IsAttestationMediaType(mediaType), mediaType)
		if expect == nil {
			require.Nil(t, parser, mediaType)
			continue
		}
		require.IsType(t, expect, parser, mediaType)
	}
}
