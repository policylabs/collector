// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"context"
	"os"
	"testing"
	"testing/fstest"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/filters"
)

func TestFetch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		exts        []string
		expect      int
		ignoreOther bool
		mustErr     bool
	}{
		{"all-default", nil, 2, true, false},
		{"ext-spdx", []string{"spdx"}, 1, true, false},
		{"ext-spdx-no-ignore", []string{"spdx"}, 2, false, false},
		{"subpath", nil, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithFS(os.DirFS("testdata")))
			// This is hardcoded but we only have on subpath test
			if tc.name == "subpath" {
				collector, err = New(
					WithFS(os.DirFS("testdata")),
					WithPath("subdir"),
				)
			}
			require.NoError(t, err)
			collector.IgnoreOtherFiles = tc.ignoreOther
			if tc.exts != nil {
				collector.Extensions = tc.exts
			}
			atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}

func TestFetchSkipsUnparseableFiles(t *testing.T) {
	t.Parallel()

	good, err := os.ReadFile("testdata/results.intoto.json")
	require.NoError(t, err)

	fsys := fstest.MapFS{
		"results.intoto.json": &fstest.MapFile{Data: good},
		// Not JSON at all
		"broken.json": &fstest.MapFile{Data: []byte("{ not json")},
		// A sigstore bundle wrapping a messageSignature instead of a DSSE
		// envelope, as found in GitHub releases (eg guacsec/guac)
		"checksums.txt.bundle": &fstest.MapFile{Data: []byte(
			`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",` +
				`"messageSignature":{"messageDigest":{"algorithm":"SHA2_256",` +
				`"digest":"6cg="},"signature":"c2ln"}}`,
		)},
	}

	collector, err := New(WithFS(fsys))
	require.NoError(t, err)

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
}

func TestFetchFetchByPredicateType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		expect  int
		pt      string
		opts    attestation.FetchOptions
		mustErr bool
	}{
		{"pt-ok", 1, "https://spdx.dev/Document", attestation.FetchOptions{}, false},
		{"pt-bad", 0, "something-else", attestation.FetchOptions{}, false},
		{"pt-ok-with-synth-always", 1, "https://spdx.dev/Document", attestation.FetchOptions{
			Query: &attestation.Query{
				Filters: []attestation.Filter{&filters.AlwaysMatch{}},
			},
		}, false},
		{"pt-ok-with-synth-never", 0, "https://spdx.dev/Document", attestation.FetchOptions{
			Query: &attestation.Query{
				Filters: []attestation.Filter{&filters.NeverMatch{}},
			},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, err := New(WithFS(os.DirFS("testdata")))
			require.NoError(t, err)

			atts, err := collector.FetchByPredicateType(
				t.Context(), tc.opts, []attestation.PredicateType{attestation.PredicateType(tc.pt)},
			)
			require.NoError(t, err)
			require.Len(t, atts, tc.expect)
		})
	}
}

// TestFetchStopsWalkOnCancelledContext proves the filesystem walk checks the
// context on every entry: a cancelled context returns the context error and
// reads no attestations.
func TestFetchStopsWalkOnCancelledContext(t *testing.T) {
	t.Parallel()

	collector, err := New(WithFS(os.DirFS("testdata")))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	envs, err := collector.Fetch(ctx, attestation.FetchOptions{})
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, envs)
}

func TestFetchKeepContent(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/results.intoto.json")
	require.NoError(t, err)

	collector, err := New(WithFS(fstest.MapFS{
		"results.intoto.json": &fstest.MapFile{Data: data},
	}))
	require.NoError(t, err)

	atts, err := collector.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.Nil(t, envelope.OriginContent(atts[0].GetPredicate()), "content is not kept unless asked")

	atts, err = collector.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.Equal(t, data, envelope.OriginContent(atts[0].GetPredicate()))
}
