// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	ita "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"
)

const (
	// Values from the immutable release openvex/discovery@v0.1.1, whose
	// attestation is captured in testdata/release-attestation.json.
	testTagSHA        = "981223e14358c7d2e069ccbf76a46cc5dabb2448"
	releasePredicate  = attestation.PredicateType("https://in-toto.io/attestation/release/v0.2")
	releaseAttPath    = "testdata/release-attestation.json"
	releaseAttestsURL = "GET /repos/example/repo/attestations/sha1:" + testTagSHA
)

// noAssets stands in for the filesystem driver and returns no attestations.
type noAssets struct{}

func (noAssets) Fetch(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, nil
}

// releaseServer serves the three endpoints the immutable-release lookup hits.
// The attestations handler is optional; when nil the endpoint answers 404.
func releaseServer(t *testing.T, immutable bool, attHandler http.HandlerFunc) *Collector {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/example/repo/releases/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{"id": 4242, "tag_name": "v1.0.0", "immutable": immutable})
		if err != nil {
			t.Errorf("encoding release: %v", err)
		}
	})
	mux.HandleFunc("GET /repos/example/repo/git/ref/tags/v1.0.0", func(w http.ResponseWriter, _ *http.Request) {
		err := json.NewEncoder(w).Encode(map[string]any{"object": map[string]any{"sha": testTagSHA, "type": "tag"}})
		if err != nil {
			t.Errorf("encoding ref: %v", err)
		}
	})
	if attHandler != nil {
		mux.HandleFunc(releaseAttestsURL, attHandler)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := testCollector(srv.URL)
	c.Driver = noAssets{}
	return c
}

func serveFixture(t *testing.T) http.HandlerFunc {
	t.Helper()
	data, err := os.ReadFile(releaseAttPath)
	require.NoError(t, err)
	return func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(data); err != nil {
			t.Errorf("writing fixture: %v", err)
		}
	}
}

func TestFetchReleaseAttestations(t *testing.T) {
	t.Parallel()

	t.Run("immutable-release", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, serveFixture(t))

		atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 1)

		st := atts[0].GetStatement()
		require.NotNil(t, st)
		require.Equal(t, releasePredicate, st.GetPredicateType())
		require.Len(t, st.GetSubjects(), 1)
		require.Equal(t, testTagSHA, st.GetSubjects()[0].GetDigest()["sha1"])
	})

	t.Run("mutable-release-skips-lookup", func(t *testing.T) {
		t.Parallel()
		var called atomic.Bool
		c := releaseServer(t, false, func(http.ResponseWriter, *http.Request) { called.Store(true) })

		atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Empty(t, atts)
		require.False(t, called.Load(), "attestations endpoint must not be queried for mutable releases")
	})

	t.Run("no-attestations-is-not-an-error", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, nil)

		atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Empty(t, atts)
	})

	t.Run("fetch-by-subject", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, serveFixture(t))

		match := &ita.ResourceDescriptor{Digest: map[string]string{"sha1": testTagSHA}}
		atts, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{match})
		require.NoError(t, err)
		require.Len(t, atts, 1)

		other := &ita.ResourceDescriptor{Digest: map[string]string{"sha1": "0000000000000000000000000000000000000000"}}
		atts, err = c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{other})
		require.NoError(t, err)
		require.Empty(t, atts)
	})

	t.Run("fetch-by-predicate-type", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, serveFixture(t))

		atts, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{releasePredicate})
		require.NoError(t, err)
		require.Len(t, atts, 1)

		atts, err = c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{"https://slsa.dev/provenance/v1"})
		require.NoError(t, err)
		require.Empty(t, atts)
	})

	t.Run("limit-already-met-abandons-lookup", func(t *testing.T) {
		t.Parallel()
		// The assets are only handed over once the lookup has reached the
		// attestations endpoint, which then waits to be abandoned: the fetch
		// can only return if the two run side by side and the limit cuts the
		// lookup short.
		reached := make(chan struct{})
		abandoned := make(chan struct{})
		c := releaseServer(t, true, func(_ http.ResponseWriter, r *http.Request) {
			close(reached)
			<-r.Context().Done()
			close(abandoned)
		})
		c.Driver = &fixedDriver{n: 2, wait: reached}

		atts, err := c.Fetch(t.Context(), attestation.FetchOptions{Limit: 2})
		require.NoError(t, err)
		require.Len(t, atts, 2)

		select {
		case <-abandoned:
		case <-time.After(10 * time.Second):
			t.Fatal("the release attestations lookup was not abandoned")
		}
	})

	t.Run("assets-come-first", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, serveFixture(t))
		c.Driver = &fixedDriver{n: 2}

		atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 3)
		require.IsType(t, fakeEnvelope{}, atts[0])
		require.IsType(t, fakeEnvelope{}, atts[1])
		require.Equal(t, releasePredicate, atts[2].GetStatement().GetPredicateType())

		atts, err = c.Fetch(t.Context(), attestation.FetchOptions{Limit: 3})
		require.NoError(t, err)
		require.Len(t, atts, 3)
	})

	t.Run("assets-error-wins", func(t *testing.T) {
		t.Parallel()
		c := releaseServer(t, true, serveFixture(t))
		c.Driver = failingDriver{}

		_, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.ErrorIs(t, err, errAssets)
	})
}

// TestFetchReleaseAttestationsAnonymous cannot run in parallel: it clears the
// token environment variables.
func TestFetchReleaseAttestationsAnonymous(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	var auth atomic.Pointer[string]
	c := releaseServer(t, true, func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		auth.Store(&h)
		serveFixture(t)(w, r)
	})
	c.Options.Token = ""

	atts, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, atts, 1)
	require.NotNil(t, auth.Load())
	require.Empty(t, *auth.Load())
}

// fixedDriver returns n placeholder envelopes, standing in for release assets.
// When wait is set it only answers once the channel is closed.
type fixedDriver struct {
	n    int
	wait <-chan struct{}
}

func (d *fixedDriver) Fetch(ctx context.Context, _ attestation.FetchOptions) ([]attestation.Envelope, error) {
	if d.wait != nil {
		select {
		case <-d.wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	envs := make([]attestation.Envelope, d.n)
	for i := range envs {
		envs[i] = fakeEnvelope{}
	}
	return envs, nil
}

var errAssets = errors.New("reading assets")

// failingDriver stands in for release assets that cannot be read.
type failingDriver struct{}

func (failingDriver) Fetch(context.Context, attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, errAssets
}
