// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"os"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/predicate/generic"
)

func TestParse(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		path       string
		data       []byte
		mustErr    bool
		checkError error
		validate   func(*testing.T, *generic.Predicate)
	}{
		{"commit", "testdata/commit.json", nil, false, nil, func(t *testing.T, p *generic.Predicate) {
			t.Helper()
			require.Equal(t, PredicateTypeCommit, p.Type)
			commit, ok := p.Parsed.(*Commit)
			require.True(t, ok)
			require.Equal(t, "0123456789abcdef0123456789abcdef01234567", commit.Tree)
			require.Len(t, commit.Parents, 1)
			require.Equal(t, "noreply@github.com", commit.Committer.Email)
			require.Equal(t, "minor", commit.Trailers.Get("Tag-commit-as"))
		}},
		{"tag", "testdata/tag.json", nil, false, nil, func(t *testing.T, p *generic.Predicate) {
			t.Helper()
			require.Equal(t, PredicateTypeTag, p.Type)
			tag, ok := p.Parsed.(*Tag)
			require.True(t, ok)
			require.Equal(t, "v1.2.0", tag.Name)
			require.Equal(t, "commit", tag.ObjectType)
			require.Equal(t, "7", tag.Trailers.Get("Pull-Request"))
			require.Empty(t, tag.Trailers.Get("Absent"))
		}},
		{"other-json", "", []byte(`{"chido":1, "mas": "no"}`), true, attestation.ErrNotCorrectFormat, nil},
		{"both-tree-and-object", "", []byte(`{"tree":"a","object":"b"}`), true, attestation.ErrNotCorrectFormat, nil},
		{"commit-with-foreign-fields", "", []byte(`{"tree":"a","signature":"x"}`), true, attestation.ErrNotCorrectFormat, nil},
		{"invalid-json", "", []byte(`"tree":1`), true, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.path != "" {
				data, err := os.ReadFile(tc.path)
				require.NoError(t, err)
				tc.data = data
			}
			pred, err := New().Parse(tc.data)
			if tc.mustErr {
				require.Error(t, err)
				if tc.checkError != nil {
					require.ErrorIs(t, err, tc.checkError)
				}
				return
			}
			require.NoError(t, err)
			p, ok := pred.(*generic.Predicate)
			require.True(t, ok)
			require.Equal(t, tc.data, p.Data)
			tc.validate(t, p)
		})
	}
}

func TestSupportsType(t *testing.T) {
	t.Parallel()
	p := New()
	require.True(t, p.SupportsType(PredicateTypeCommit))
	require.True(t, p.SupportsType("https://example.com/other", PredicateTypeTag))
	require.False(t, p.SupportsType("https://gitsign.sigstore.dev/predicate/git/v0.1"))
}

func TestParseTrailers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		message string
		want    Trailers
	}{
		{"none", "Subject only\n", nil},
		{"subject-is-not-a-trailer-block", "Fix: the thing\n", nil},
		{"body-without-trailers", "Subject\n\nA body paragraph.\n", nil},
		{"one", "Subject\n\nBody.\n\nSigned-off-by: A <a@x>\n", Trailers{"Signed-off-by": {"A <a@x>"}}},
		{
			"several-and-repeated", "Subject\n\nEvaluated-Commit: abc\nPull-Request: 7\nSigned-off-by: A <a@x>\nSigned-off-by: B <b@x>\n",
			Trailers{"Evaluated-Commit": {"abc"}, "Pull-Request": {"7"}, "Signed-off-by": {"A <a@x>", "B <b@x>"}},
		},
		{"continuation", "Subject\n\nNote: first line\n  second line\nOther: v\n", Trailers{"Note": {"first line\nsecond line"}, "Other": {"v"}}},
		{"mixed-block-is-not-trailers", "Subject\n\nSome prose here\nSigned-off-by: A <a@x>\n", nil},
		{"crlf", "Subject\r\n\r\nKey: value\r\n", Trailers{"Key": {"value"}}},
		{"token-with-space-is-not-a-trailer", "Subject\n\nNot a: trailer\n", nil},
		{"no-space-after-colon", "Subject\n\nKey:value\n", Trailers{"Key": {"value"}}},
		{
			"release-tag", "Release v1.2.0\n\nCut by miniprow from a minor release request.\n\nPolicies verified:\n- gitsign\n\nEvaluated-Commit: deadbeef\nPull-Request: 7\nTree: 0123\nMerge-Strategy: squash\n",
			Trailers{"Evaluated-Commit": {"deadbeef"}, "Pull-Request": {"7"}, "Tree": {"0123"}, "Merge-Strategy": {"squash"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, ParseTrailers(tc.message))
		})
	}
}
