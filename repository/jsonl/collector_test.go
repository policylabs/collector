// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package jsonl

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/envelope"
)

func TestParseJsonlFile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		srcData      string
		mustErr      bool
		expectedAtts int
	}{
		{"single", "testdata/single.jsonl", false, 1},
		{"badline", "testdata/bad.jsonl", false, 2}, // Bad line in the middle
		{"multiple", "testdata/multiple.jsonl", false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			atts, err := parseJsonlFile(&attestation.FetchOptions{}, tc.srcData, nil)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tc.expectedAtts)
		})
	}
}

func TestReadAttestations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		files        []string
		mustErr      bool
		expectedAtts int
	}{
		{"single", []string{"testdata/single.jsonl"}, false, 1},
		// The parser should be resilient to a bad line in the jsonl data
		{"bad", []string{"testdata/bad.jsonl"}, false, 2},
		{"multiple", []string{"testdata/multiple.jsonl", "testdata/single.jsonl"}, false, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := Collector{
				Options: Options{
					MaxParallel: 3,
					Paths:       []string{},
				},
			}
			atts, err := c.readAttestations(&attestation.FetchOptions{}, tc.files, nil)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, atts, tc.expectedAtts)
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	t.Run("plain-new", func(t *testing.T) {
		t.Parallel()
		c, err := New()
		require.NoError(t, err)
		require.NotNil(t, c)
	})
	t.Run("with-path", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithPath("testdata/single.jsonl"))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, []string{"testdata/single.jsonl"}, c.Options.Paths)
	})
	t.Run("with-maxp", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithMaxParallel(1000))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.Equal(t, 1000, c.Options.MaxParallel)
	})
	t.Run("with-error", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithPath("badfile"))
		require.Error(t, err)
	})
}

func TestParseJsonlFileKeepContent(t *testing.T) {
	t.Parallel()
	const path = "testdata/multiple.jsonl"

	atts, err := parseJsonlFile(&attestation.FetchOptions{}, path, nil)
	require.NoError(t, err)
	for _, att := range atts {
		require.Nil(t, envelope.OriginContent(att.GetPredicate()), "content is not kept unless asked")
	}

	atts, err = parseJsonlFile(&attestation.FetchOptions{KeepContent: true}, path, nil)
	require.NoError(t, err)
	require.Len(t, atts, 6)
	for _, att := range atts {
		origin := att.GetPredicate().GetOrigin()
		content := envelope.OriginContent(att.GetPredicate())
		require.NotEmpty(t, content)

		// The origin still names the line the attestation was read from and
		// its digest is that of the content kept.
		require.Contains(t, origin.GetUri(), "jsonl:"+path+"#")
		sum := sha256.Sum256(content)
		require.Equal(t, hex.EncodeToString(sum[:]), origin.GetDigest()["sha256"])
	}
}
