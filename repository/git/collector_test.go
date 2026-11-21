// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/release-utils/tar"

	gitpred "github.com/policylabs/collector/predicate/git"
	"github.com/policylabs/collector/repository/filesystem"
)

func TestClone(t *testing.T) {
	t.Parallel()

	// unpack test repository to tmp
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	logrus.Info(filepath.Join(dir, "repo"))
	for _, tc := range []struct {
		name        string
		init        string
		expectedNum int
		mustErr     bool
	}{
		// Three files at the root, two under sboms, plus the attestation
		// describing the checked-out commit.
		{"root", filepath.Join(dir, "repo"), 4, false},
		{"subpath", filepath.Join(dir, "repo") + "#sboms", 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithLocator(tc.init))
			require.NoError(t, err)

			err = c.clone(t.Context())
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Check if the methods work
			res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, res, tc.expectedNum)
		})
	}
}

func TestCloneExtensions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	repo := filepath.Join(dir, "repo")

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithLocator(repo))
		require.NoError(t, err)
		require.NoError(t, c.clone(t.Context()))
		require.Equal(t, filesystem.DefaultExtensions, c.FSCollector.Extensions)
	})

	t.Run("custom", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithLocator(repo), WithExtensions([]string{"spdx"}))
		require.NoError(t, err)
		require.NoError(t, c.clone(t.Context()))
		require.Equal(t, []string{"spdx"}, c.FSCollector.Extensions)

		// Only the spdx documents in the fixture are read now
		res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		for _, env := range res {
			if env.GetStatement().GetPredicateType() == gitpred.PredicateTypeCommit {
				continue
			}
			require.Contains(t, string(env.GetStatement().GetPredicateType()), "spdx")
		}
	})
}

// TestFetchHonorsContext proves the clone respects the caller's context: a
// pre-cancelled context must fail with context.Canceled before reaching the
// remote, not with a network error from the unreachable address.
func TestFetchHonorsContext(t *testing.T) {
	t.Parallel()
	c, err := New(WithLocator("https://127.0.0.1:1/org/repo"))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = c.Fetch(ctx, attestation.FetchOptions{})
	require.ErrorIs(t, err, context.Canceled)
}

// fixtureRepo unpacks the fixture repository and returns its path and the
// commit at its HEAD.
func fixtureRepo(t *testing.T) (string, plumbing.Hash) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, tar.Extract("testdata/repo.tar.gz", dir))
	path := filepath.Join(dir, "repo")
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	return path, head.Hash()
}

// The checked-out commit is described whatever the locator: a plain path
// lands on HEAD, and the attestation's subjects are the commit and its tree.
func TestDescribesHeadCommit(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	c, err := New(WithLocator(path))
	require.NoError(t, err)
	res, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{gitpred.PredicateTypeCommit})
	require.NoError(t, err)
	require.Len(t, res, 1)
	subjects := res[0].GetStatement().GetSubjects()
	require.Len(t, subjects, 2)
	require.Equal(t, head.String(), subjects[0].GetDigest()["gitCommit"])
	require.NotEmpty(t, subjects[1].GetDigest()["gitTree"])
	commit, ok := res[0].GetPredicate().GetParsed().(*gitpred.Commit)
	require.True(t, ok)
	require.True(t, strings.HasPrefix(commit.Message, "Add CycloneDX sbom in subdir\n"), commit.Message)
	require.Contains(t, commit.Trailers.Get("Signed-off-by"), "puerco")

	// And it is found by its sha.
	bySubject, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{
		&intoto.ResourceDescriptor{Digest: map[string]string{"sha1": head.String()}},
	})
	require.NoError(t, err)
	require.Len(t, bySubject, 1)
}

// An annotated tag in the locator is described too: the clone lands on the
// tag, and the tag attestation names the tag object and its target, with
// the message's trailers parsed.
func TestDescribesAnnotatedTag(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	tagRef, err := repo.CreateTag("v1.0.0", head, &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "Tester", Email: "tester@example.com", When: time.Now()},
		Message: "Release v1.0.0\n\nEvaluated-Commit: " + head.String() + "\nPull-Request: 7\n",
	})
	require.NoError(t, err)

	for _, locator := range []string{path + "@v1.0.0", path + "@refs/tags/v1.0.0"} {
		c, err := New(WithLocator(locator))
		require.NoError(t, err)
		res, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, res, 5, "three files, the commit and the tag")

		tags, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{gitpred.PredicateTypeTag})
		require.NoError(t, err)
		require.Len(t, tags, 1)
		tag, ok := tags[0].GetPredicate().GetParsed().(*gitpred.Tag)
		require.True(t, ok)
		require.Equal(t, "v1.0.0", tag.Name)
		require.Equal(t, head.String(), tag.Object)
		require.Equal(t, head.String(), tag.Trailers.Get("Evaluated-Commit"))
		subjects := tags[0].GetStatement().GetSubjects()
		require.Equal(t, tagRef.Hash().String(), subjects[0].GetDigest()["gitTag"])
		require.Equal(t, head.String(), subjects[1].GetDigest()["gitCommit"])
	}
}

// A lightweight tag has no object: the locator lands on its commit, which is
// described, and no tag attestation is produced.
func TestLightweightTagDescribesCommitOnly(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	_, err = repo.CreateTag("light", head, nil)
	require.NoError(t, err)
	c, err := New(WithLocator(path + "@light"))
	require.NoError(t, err)
	res, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{gitpred.PredicateTypeCommit, gitpred.PredicateTypeTag})
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, gitpred.PredicateTypeCommit, res[0].GetStatement().GetPredicateType())
}

// A short branch name resolves against the remote like a tag does.
func TestShortBranchRef(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	c, err := New(WithLocator(path + "@master"))
	require.NoError(t, err)
	res, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{gitpred.PredicateTypeCommit})
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, head.String(), res[0].GetStatement().GetSubjects()[0].GetDigest()["gitCommit"])

	_, err = New(WithLocator(path + "@nope"))
	require.NoError(t, err)
	c, err = New(WithLocator(path + "@nope"))
	require.NoError(t, err)
	_, err = c.Fetch(t.Context(), attestation.FetchOptions{})
	require.ErrorContains(t, err, "neither a tag nor a branch")
}

// A commit sha in the locator fetches that commit alone and describes it.
func TestCommitRef(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	headCommit, err := repo.CommitObject(head)
	require.NoError(t, err)
	parent := headCommit.ParentHashes[0]
	for _, ref := range []string{parent.String(), parent.String()[:7]} {
		c, err := New(WithLocator(path + "@" + ref))
		require.NoError(t, err)
		res, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{gitpred.PredicateTypeCommit})
		require.NoError(t, err)
		require.Len(t, res, 1)
		require.Equal(t, parent.String(), res[0].GetStatement().GetSubjects()[0].GetDigest()["gitCommit"])
		// The checkout is that commit's tree: two files fewer than HEAD's.
		all, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Len(t, all, 3, "two files at that commit plus the commit attestation")
	}
}

// A subject query for a commit the locator did not land on fetches that
// commit and describes it, so a chain reaching a commit on no branch still
// finds its attestation; a sha that is no commit yields nothing.
func TestFetchBySubjectDescribesOtherCommits(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	headCommit, err := repo.CommitObject(head)
	require.NoError(t, err)
	parent := headCommit.ParentHashes[0]
	c, err := New(WithLocator(path))
	require.NoError(t, err)
	query := func(sha string) []attestation.Envelope {
		t.Helper()
		res, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{}, []attestation.Subject{
			&intoto.ResourceDescriptor{Digest: map[string]string{"gitCommit": sha}},
		})
		require.NoError(t, err)
		return res
	}
	res := query(parent.String())
	require.Len(t, res, 1)
	require.Equal(t, gitpred.PredicateTypeCommit, res[0].GetStatement().GetPredicateType())
	require.Equal(t, parent.String(), res[0].GetStatement().GetSubjects()[0].GetDigest()["gitCommit"])
	require.Len(t, query(parent.String()), 1, "the described commit is remembered")
	require.Empty(t, query("ffffffffffffffffffffffffffffffffffffffff"))
	require.Len(t, query(head.String()), 1, "the checked-out commit is still served from the clone")
}

// The credentials go out with every request to the remote, whichever way
// the locator makes the collector reach it: resolving a short ref, cloning
// a full one, fetching a commit by sha, and fetching another commit for a
// subject query. The remote here answers nothing useful: what it saw is
// what the test is about.
func TestAuthIsSentToTheRemote(t *testing.T) {
	t.Parallel()
	const sha = "26c86b565d84be21e02361ba939bbcbf19e39e33"
	for _, tc := range []struct {
		name string
		ref  string
	}{
		{name: "short ref, resolved on the remote", ref: "v1.0.0"},
		{name: "full ref, cloned", ref: "refs/tags/v1.0.0"},
		{name: "commit, fetched by sha", ref: sha},
		{name: "no ref, the remote's HEAD", ref: ""},
	} {
		for _, token := range []string{"s3cret", ""} {
			t.Run(fmt.Sprintf("%s, token %q", tc.name, token), func(t *testing.T) {
				t.Parallel()
				var mu sync.Mutex
				var requests, authed int
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					requests++
					if user, pass, ok := r.BasicAuth(); ok && user == "x-access-token" && pass == "s3cret" {
						authed++
					}
					http.Error(w, "nothing here", http.StatusNotFound)
				}))
				t.Cleanup(srv.Close)

				c, err := New(WithToken(token), func(o *Options) error {
					o.URL, o.Ref = srv.URL+"/org/repo", tc.ref
					return nil
				})
				require.NoError(t, err)
				_, err = c.Fetch(t.Context(), attestation.FetchOptions{})
				require.Error(t, err, "the remote serves no repository")

				mu.Lock()
				defer mu.Unlock()
				require.Positive(t, requests, "the remote was never asked")
				if token == "" {
					require.Zero(t, authed, "credentials sent without a token")
					require.Nil(t, c.Options.Auth)
				} else {
					require.Equal(t, requests, authed, "a request went out without the credentials")
				}
			})
		}
	}

	// A commit fetched on demand for a subject query takes them too.
	t.Run("commit described for a subject query", func(t *testing.T) {
		t.Parallel()
		var mu sync.Mutex
		var requests, authed int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			requests++
			if _, pass, ok := r.BasicAuth(); ok && pass == "s3cret" {
				authed++
			}
			http.Error(w, "nothing here", http.StatusNotFound)
		}))
		t.Cleanup(srv.Close)

		c, err := New(WithAuth(&githttp.BasicAuth{Username: "x-access-token", Password: "s3cret"}))
		require.NoError(t, err)
		c.Options.URL = srv.URL + "/org/repo"
		require.Nil(t, c.describeCommit(t.Context(), sha))

		mu.Lock()
		defer mu.Unlock()
		require.Positive(t, requests)
		require.Equal(t, requests, authed)
	})
}
