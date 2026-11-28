// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/carabiner-dev/github"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
)

// failingCaller answers every request with an empty 200 except the ones
// whose ordinal is listed in failOn, which fail with the given error.
type failingCaller struct {
	calls  int
	failOn map[int]error
}

func (fc *failingCaller) RequestWithContext(_ context.Context, _, _ string, _ io.Reader) (*http.Response, error) {
	i := fc.calls
	fc.calls++
	if err, ok := fc.failOn[i]; ok {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

func TestStore(t *testing.T) {
	t.Parallel()
	envs, err := envelope.Parsers.ParseFiles([]string{
		"../../envelope/bundle/testdata/bundle-provenance.json",
		"../../envelope/bundle/testdata/bundle-publish.json",
		"../../envelope/bundle/testdata/bundle-provenance.json",
	})
	require.NoError(t, err)
	require.Len(t, envs, 3)

	rejected := errors.New("HTTP Error 422 sending request: invalid statement")
	for _, tc := range []struct {
		name         string
		failOn       map[int]error
		expectStored int
		expectFailed []int
	}{
		{"all-stored", nil, 3, nil},
		{"one-rejected", map[int]error{1: rejected}, 2, []int{1}},
		{"all-rejected", map[int]error{0: rejected, 1: rejected, 2: rejected}, 0, []int{0, 1, 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			caller := &failingCaller{failOn: tc.failOn}
			client, err := github.NewClient(github.WithCaller(caller), github.WithEnsureToken(false))
			require.NoError(t, err)
			collector := &Collector{Options: Options{Owner: "org", Repo: "repo"}, client: client}

			err = collector.Store(t.Context(), attestation.StoreOptions{}, envs)
			require.Equal(t, len(envs), caller.calls, "every envelope must be attempted")
			if tc.expectFailed == nil {
				require.NoError(t, err)
				return
			}

			var serr *repository.StoreError
			require.ErrorAs(t, err, &serr)
			require.Equal(t, tc.expectStored, serr.Stored)
			require.Len(t, serr.Failed, len(tc.expectFailed))
			for _, i := range tc.expectFailed {
				require.ErrorIs(t, serr.Failed[i], rejected)
			}
			require.Equal(t, tc.expectStored == 0, serr.AllFailed())
		})
	}
}

func TestFetchFromUrl(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		srcData      string
		synterr      error
		expectedAtts int
	}{
		{"normal", "testdata/output.json", nil, 2},
		{"err", "", errors.New("bad boi"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create the mocked client
			client, err := github.NewClient(
				github.WithCaller(
					&github.FileCaller{
						SourcePath: tc.srcData,
						Error:      tc.synterr,
					},
				),
				github.WithEnsureToken(false),
			)
			require.NoError(t, err)

			collector := &Collector{
				Options: Options{},
				client:  client,
			}

			// Call the fetch
			res, _, err := collector.fetchFromUrl(
				t.Context(),
				"users/carabiner-dev/attestations/sha256:2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f",
				attestation.FetchOptions{},
			)
			if tc.synterr != nil {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, res, tc.expectedAtts)
		})
	}
}

func TestWithRepo(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		sut          string
		expectedOrg  string
		expectedRepo string
		start        *Options
	}{
		{"slug", "protobom/cel", "protobom", "cel", &Options{}},
		{"repo", "cel", "", "cel", &Options{}},
		{"blank", "", "", "", &Options{}},
		{"no-overwrite", "cel", "protobom", "cel", &Options{Owner: "protobom"}},
		{"host-prefix", "github.com/protobom/cel", "protobom", "cel", &Options{}},
		{"url", "https://github.com/protobom/cel", "protobom", "cel", &Options{}},
		{"url-git", "https://github.com/protobom/cel.git", "protobom", "cel", &Options{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := WithRepo(tc.sut)
			f(tc.start)
			require.Equal(t, tc.expectedOrg, tc.start.Owner)
			require.Equal(t, tc.expectedRepo, tc.start.Repo)
		})
	}
}

// TestFetchBySubjectDedupes checks that a subject with several digests,
// which makes the API return the same attestations once per digest, only
// yields each attestation once.
func TestFetchBySubjectDedupes(t *testing.T) {
	t.Parallel()
	client, err := github.NewClient(
		github.WithCaller(&github.FileCaller{SourcePath: "testdata/output.json"}),
		github.WithEnsureToken(false),
	)
	require.NoError(t, err)
	collector := &Collector{Options: Options{Owner: "org", Repo: "repo"}, client: client}

	subject := &intoto.ResourceDescriptor{Digest: map[string]string{
		"sha256": "2775bba8b2170bef2f91b79d4f179fd87724ffee32b4a20b8304856fd3bf4b8f",
		"sha512": "9a4e4c8c0c0f6a3c1b2d6f0e5c6a5e7a2d4c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e",
	}}
	res, err := collector.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{subject})
	require.NoError(t, err)
	// testdata/output.json holds two attestations, served for both digests
	require.Len(t, res, 2)
}
