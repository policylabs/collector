// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAnnotate(t *testing.T) {
	t.Parallel()

	t.Run("round-trip", func(t *testing.T) {
		t.Parallel()
		// Annotations other than ours are left alone
		origin := &intoto.ResourceDescriptor{Annotations: &structpb.Struct{
			Fields: map[string]*structpb.Value{"other": structpb.NewStringValue("kept")},
		}}
		material := map[string]any{"file": "a.whl", "publisher": map[string]any{"kind": "GitHub"}}
		require.NoError(t, Annotate(origin, "pypi", material))

		// As it reads after travelling serialized
		data, err := protojson.Marshal(origin)
		require.NoError(t, err)
		read := &intoto.ResourceDescriptor{}
		require.NoError(t, protojson.Unmarshal(data, read))

		require.Equal(t, "pypi", Annotated(read))
		require.Equal(t, material, Material(read))
		require.Equal(t, "kept", read.GetAnnotations().GetFields()["other"].GetStringValue())
	})

	t.Run("not-annotated", func(t *testing.T) {
		t.Parallel()
		require.Empty(t, Annotated(nil))
		require.Nil(t, Material(nil))
		require.Empty(t, Annotated(&intoto.ResourceDescriptor{}))
		require.Nil(t, Material(&intoto.ResourceDescriptor{}))
	})

	t.Run("errors", func(t *testing.T) {
		t.Parallel()
		require.Error(t, Annotate(nil, "pypi", nil))
		require.Error(t, Annotate(&intoto.ResourceDescriptor{}, "", nil))
		// Material that cannot be an annotation
		require.Error(t, Annotate(&intoto.ResourceDescriptor{}, "pypi", map[string]any{"bad": make(chan int)}))
	})
}
