// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

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
