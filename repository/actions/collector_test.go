// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/repository/filesystem"
)

const (
	fixturePredicateType = "https://carabiner.dev/ampel/results/v0.0.1"
	fixtureSHA256        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// statement returns the fixture attestation, a bare in-toto statement.
func statement(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/results.intoto.json")
	require.NoError(t, err)
	return data
}

// zipArchive builds a zip archive in memory.
func zipArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// fakeGitHub serves a run's artifact listing and downloads the way the GitHub
// API does: the download endpoint redirects to a separate blob server that
// must never see the token.
type fakeGitHub struct {
	api      *httptest.Server
	blob     *httptest.Server
	listing  []artifact
	archives map[int64][]byte

	// failListings makes that many listing requests fail with a 500 first.
	failListings atomic.Int32
	// direct serves archives from the API host instead of redirecting.
	direct bool

	mu        sync.Mutex
	downloads []int64
	pages     []string
	apiAuth   []string
	blobAuth  []string
}

func newFakeGitHub(t *testing.T, listing []artifact, archives map[int64][]byte) *fakeGitHub {
	t.Helper()
	f := &fakeGitHub{listing: listing, archives: archives}

	f.blob = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.blobAuth = append(f.blobAuth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		f.serveArchive(t, w, strings.TrimPrefix(r.URL.Path, "/blob/"))
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/example/repo/actions/runs/42/artifacts", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.apiAuth = append(f.apiAuth, r.Header.Get("Authorization"))
		f.pages = append(f.pages, r.URL.Query().Get("page"))
		f.mu.Unlock()
		if f.failListings.Add(-1) >= 0 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		if err != nil || page < 1 {
			http.Error(w, "bad page", http.StatusBadRequest)
			return
		}
		perPage, err := strconv.Atoi(r.URL.Query().Get("per_page"))
		if err != nil || perPage < 1 {
			http.Error(w, "bad per_page", http.StatusBadRequest)
			return
		}
		start := min((page-1)*perPage, len(f.listing))
		end := min(start+perPage, len(f.listing))
		if err := json.NewEncoder(w).Encode(artifactList{
			TotalCount: len(f.listing),
			Artifacts:  f.listing[start:end],
		}); err != nil {
			t.Errorf("encoding listing: %v", err)
		}
	})
	mux.HandleFunc("GET /repos/example/repo/actions/artifacts/{id}/zip", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.apiAuth = append(f.apiAuth, r.Header.Get("Authorization"))
		f.mu.Unlock()
		if f.direct {
			f.serveArchive(t, w, r.PathValue("id"))
			return
		}
		w.Header().Set("Location", f.blob.URL+"/blob/"+r.PathValue("id"))
		w.WriteHeader(http.StatusFound)
	})
	f.api = httptest.NewServer(mux)
	t.Cleanup(f.api.Close)
	t.Cleanup(f.blob.Close)
	return f
}

func (f *fakeGitHub) serveArchive(t *testing.T, w http.ResponseWriter, idStr string) {
	t.Helper()
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.downloads = append(f.downloads, id)
	data, ok := f.archives[id]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "no such artifact", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	if _, err := w.Write(data); err != nil {
		t.Errorf("writing archive: %v", err)
	}
}

// seen returns copies of what the fake servers recorded.
func (f *fakeGitHub) seen() (downloads []int64, pages, apiAuth, blobAuth []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.downloads), slices.Clone(f.pages), slices.Clone(f.apiAuth), slices.Clone(f.blobAuth)
}

// collector returns a collector pointed at the fake API, configured with the
// defaults every test relies on plus funcs.
func (f *fakeGitHub) collector(t *testing.T, funcs ...optFn) *Collector {
	t.Helper()
	c, err := New(append([]optFn{
		WithHost("github.com"), WithRepo("example/repo"), WithRunID(42),
		WithToken("s3cr3t"), WithRetries(0),
	}, funcs...)...)
	require.NoError(t, err)
	c.apiBaseURL = f.api.URL
	return c
}

// standardRun returns a fake run holding a mix of artifacts:
//
//	1 results.intoto.json  one bare statement
//	2 attestations.jsonl   two statements
//	3 nested.zip           a zip inside the artifact holding one statement
//	4 binary               no extension, never downloaded
//	5 old.json             expired, never downloaded
//	6 notes.txt            extension not configured, never downloaded
//	7 mixed.json           one statement plus a nested zip holding another
func standardRun(t *testing.T) *fakeGitHub {
	t.Helper()
	stmt := statement(t)
	var line bytes.Buffer
	require.NoError(t, json.Compact(&line, stmt))
	jsonl := bytes.Join([][]byte{line.Bytes(), line.Bytes()}, []byte("\n"))

	archives := map[int64][]byte{
		1: zipArchive(t, map[string][]byte{"results.intoto.json": stmt}),
		2: zipArchive(t, map[string][]byte{"attestations.jsonl": jsonl}),
		3: zipArchive(t, map[string][]byte{
			"nested.zip": zipArchive(t, map[string][]byte{"inner/results.intoto.json": stmt}),
		}),
		4: zipArchive(t, map[string][]byte{"binary": []byte("not an attestation")}),
		5: zipArchive(t, map[string][]byte{"old.json": stmt}),
		6: zipArchive(t, map[string][]byte{"notes.txt": []byte("hello")}),
		7: zipArchive(t, map[string][]byte{
			"mixed.json": stmt,
			"more.zip":   zipArchive(t, map[string][]byte{"more.json": stmt}),
		}),
	}
	listing := []artifact{
		{ID: 1, Name: "results.intoto.json"},
		{ID: 2, Name: "attestations.jsonl"},
		{ID: 3, Name: "nested.zip"},
		{ID: 4, Name: "binary"},
		{ID: 5, Name: "old.json", Expired: true},
		{ID: 6, Name: "notes.txt"},
		{ID: 7, Name: "mixed.json"},
	}
	for i := range listing {
		listing[i].SizeInBytes = int64(len(archives[listing[i].ID]))
	}
	return newFakeGitHub(t, listing, archives)
}

func TestFetch(t *testing.T) {
	t.Parallel()

	t.Run("reads-matching-artifacts", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		atts, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 6)

		downloads, _, apiAuth, blobAuth := gh.seen()
		require.ElementsMatch(t, []int64{1, 2, 3, 7}, downloads)
		require.NotEmpty(t, apiAuth)
		for _, auth := range apiAuth {
			require.Equal(t, "Bearer s3cr3t", auth)
		}
		require.Len(t, blobAuth, 4, "every download must go through the blob server")
		for _, auth := range blobAuth {
			require.Empty(t, auth, "the token must not reach the blob server")
		}
	})

	t.Run("reads-direct-downloads", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		gh.direct = true
		atts, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 6)
		_, _, _, blobAuth := gh.seen()
		require.Empty(t, blobAuth)
	})

	t.Run("honors-limit", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		atts, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{Limit: 2})
		require.NoError(t, err)
		require.Len(t, atts, 2)
		downloads, _, _, _ := gh.seen()
		require.Equal(t, []int64{1, 2}, downloads, "downloads must stop once the limit is reached")
	})

	t.Run("filters-artifacts-by-extension", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		atts, err := gh.collector(t, WithExtensions("jsonl")).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 2)
		downloads, _, _, _ := gh.seen()
		require.Equal(t, []int64{2}, downloads)
	})

	t.Run("leaves-zips-alone-without-the-extension", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		atts, err := gh.collector(t, WithExtensions(".json", ".jsonl")).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 4, "the nested zip in mixed.json must not be expanded")
		downloads, _, _, _ := gh.seen()
		require.Equal(t, []int64{1, 2, 7}, downloads)
	})

	t.Run("rejects-oversized-artifacts", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		_, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{MaxReadSize: 64})
		require.ErrorContains(t, err, "exceeds max read size")
		downloads, _, _, _ := gh.seen()
		require.Empty(t, downloads, "oversized artifacts must not be downloaded")
	})

	t.Run("rejects-understated-sizes", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		for i := range gh.listing {
			gh.listing[i].SizeInBytes = 1
		}
		_, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{MaxReadSize: 64})
		require.ErrorContains(t, err, "exceeds max read size")
	})

	t.Run("paginates-listings", func(t *testing.T) {
		t.Parallel()
		listing := make([]artifact, 0, artifactsPerPage+1)
		for i := range artifactsPerPage {
			listing = append(listing, artifact{ID: int64(i), Name: fmt.Sprintf("file-%d.txt", i), SizeInBytes: 1})
		}
		archive := zipArchive(t, map[string][]byte{"results.intoto.json": statement(t)})
		listing = append(listing, artifact{ID: 1000, Name: "results.intoto.json", SizeInBytes: int64(len(archive))})
		gh := newFakeGitHub(t, listing, map[int64][]byte{1000: archive})

		atts, err := gh.collector(t).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 1)
		downloads, pages, _, _ := gh.seen()
		require.Equal(t, []int64{1000}, downloads)
		require.Equal(t, []string{"1", "2"}, pages)
	})

	t.Run("retries-failed-listings", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		gh.failListings.Store(1)
		atts, err := gh.collector(t, WithRetries(2)).Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, atts, 6)
		_, pages, _, _ := gh.seen()
		require.Len(t, pages, 2)
	})

	t.Run("does-not-retry-client-errors", func(t *testing.T) {
		t.Parallel()
		gh := standardRun(t)
		_, err := gh.collector(t, WithRetries(3), WithRunID(43)).Fetch(t.Context(), attestation.FetchOptions{})
		require.ErrorContains(t, err, "HTTP 404")
	})
}

func TestFetchBySubject(t *testing.T) {
	t.Parallel()
	gh := standardRun(t)
	c := gh.collector(t)

	match := &intoto.ResourceDescriptor{
		Name:   "examples/vulns/artifact",
		Digest: map[string]string{"sha256": fixtureSHA256},
	}
	atts, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{match})
	require.NoError(t, err)
	require.Len(t, atts, 6)

	other := &intoto.ResourceDescriptor{Digest: map[string]string{"sha256": strings.Repeat("0", 64)}}
	atts, err = c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{other})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestFetchByPredicateType(t *testing.T) {
	t.Parallel()
	gh := standardRun(t)
	c := gh.collector(t)

	atts, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{fixturePredicateType})
	require.NoError(t, err)
	require.Len(t, atts, 6)

	atts, err = c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{"https://example.com/other/v1"})
	require.NoError(t, err)
	require.Empty(t, atts)
}

func TestWithFilterKeepsCallerQuery(t *testing.T) {
	t.Parallel()
	query := &attestation.Query{Filters: attestation.FilterSet{&filters.PredicateTypeMatcher{}}}
	out := withFilter(attestation.FetchOptions{Query: query}, &filters.PredicateTypeMatcher{})
	require.Len(t, query.Filters, 1)
	require.Len(t, out.Query.Filters, 2)
}

func TestFetchRequiresToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	c, err := New(WithRunURL("//github.com/example/repo/run/42"))
	require.NoError(t, err)
	_, err = c.Fetch(t.Context(), attestation.FetchOptions{})
	require.ErrorContains(t, err, "token is required")
}

func TestBuild(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		init    string
		host    string
		owner   string
		repo    string
		runID   int64
		mustErr bool
	}{
		{"registry-form", "//github.com/carabiner-labs/baseline-init/run/34180821665", "github.com", "carabiner-labs", "baseline-init", 34180821665, false},
		{"full-locator", "actions://github.com/carabiner-labs/baseline-init/run/34180821665", "github.com", "carabiner-labs", "baseline-init", 34180821665, false},
		{"enterprise-server", "//ghe.example.com/org/repo/run/7", "ghe.example.com", "org", "repo", 7, false},
		{"enterprise-with-port", "//ghe.example.com:8443/org/repo/run/7", "ghe.example.com:8443", "org", "repo", 7, false},
		{"trailing-slash", "//github.com/org/repo/run/7/", "github.com", "org", "repo", 7, false},
		{"no-host", "actions:org/repo/run/7", "", "", "", 0, true},
		{"missing-run", "//github.com/org/repo", "", "", "", 0, true},
		{"wrong-namespace", "//github.com/org/repo/runs/7", "", "", "", 0, true},
		{"non-numeric-run", "//github.com/org/repo/run/latest", "", "", "", 0, true},
		{"zero-run", "//github.com/org/repo/run/0", "", "", "", 0, true},
		{"extra-segments", "//github.com/org/repo/run/7/artifact", "", "", "", 0, true},
		{"other-scheme", "https://github.com/org/repo/run/7", "", "", "", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			repo, err := Build(tc.init)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			c, ok := repo.(*Collector)
			require.True(t, ok)
			require.Equal(t, tc.host, c.Options.Host)
			require.Equal(t, tc.owner, c.Options.Owner)
			require.Equal(t, tc.repo, c.Options.Repo)
			require.Equal(t, tc.runID, c.Options.RunID)
		})
	}
}

func TestAPIBaseURL(t *testing.T) {
	t.Parallel()
	for host, expected := range map[string]string{
		"github.com":           "https://api.github.com",
		"GitHub.com":           "https://api.github.com",
		"api.github.com":       "https://api.github.com",
		"octocorp.ghe.com":     "https://api.octocorp.ghe.com",
		"ghe.example.com":      "https://ghe.example.com/api/v3",
		"ghe.example.com:8443": "https://ghe.example.com:8443/api/v3",
	} {
		require.Equal(t, expected, apiBaseURL(host), host)
	}

	c, err := New(WithRunURL("//octocorp.ghe.com/org/repo/run/7"))
	require.NoError(t, err)
	require.Equal(t, "https://api.octocorp.ghe.com", c.apiBaseURL)
}

func TestDefaultExtensions(t *testing.T) {
	t.Parallel()
	fsc, err := filesystem.New()
	require.NoError(t, err)
	require.Equal(t, append(slices.Clone(fsc.Extensions), zipExtension), defaultExtensions)

	c, err := New(WithRunURL("//github.com/example/repo/run/42"))
	require.NoError(t, err)
	require.Equal(t, defaultExtensions, c.Options.Extensions)
	require.True(t, c.Options.expandZips())
	require.NotContains(t, c.Options.fileExtensions(), zipExtension)

	_, err = New(WithRunURL("//github.com/example/repo/run/42"), WithExtensions())
	require.ErrorContains(t, err, "no artifact extensions set")
}

// requireKeptContent checks that an attestation kept content that hashes to
// the digest of its origin and returns it.
func requireKeptContent(t *testing.T, env attestation.Envelope) []byte {
	t.Helper()
	content := envelope.OriginContent(env.GetPredicate())
	require.NotEmpty(t, content)
	sum := sha256.Sum256(content)
	require.Equal(t, hex.EncodeToString(sum[:]), env.GetPredicate().GetOrigin().GetDigest()["sha256"])
	return content
}

func TestFetchKeepContent(t *testing.T) {
	t.Parallel()

	atts, err := standardRun(t).collector(t).Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	for _, att := range atts {
		require.Nil(t, envelope.OriginContent(att.GetPredicate()), "content is not kept unless asked")
	}

	// Every attestation read out of an artifact keeps its data, whether it
	// came as a file, a line of a jsonl bundle or inside a nested archive.
	atts, err = standardRun(t).collector(t).Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, atts, 6)
	for _, att := range atts {
		require.JSONEq(t, string(statement(t)), string(requireKeptContent(t, att)))
	}
}
