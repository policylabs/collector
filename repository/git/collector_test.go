// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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
