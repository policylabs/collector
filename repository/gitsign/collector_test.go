// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitsign

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/vcslocator"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	gspredicate "github.com/sigstore/gitsign/pkg/predicate"
	"github.com/stretchr/testify/require"
)

const (
	testName  = "Test"
	testEmail = "test@example.com"
	algoSHA1  = "sha1"
)

// initTestRepo creates a local git repo with a signed commit and returns
// the repo path, the commit hash, and the repo object.
func initTestRepo(t *testing.T) (repoPath, commitHash string) {
	t.Helper()

	repoPath = filepath.Join(t.TempDir(), "test-repo")
	repo, err := gogit.PlainInit(repoPath, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	testFile := filepath.Join(repoPath, "file.txt")
	err = os.WriteFile(testFile, []byte("content"), 0o600)
	require.NoError(t, err)

	_, err = wt.Add("file.txt")
	require.NoError(t, err)

	hash, err := wt.Commit("Test commit", &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  testName,
			Email: testEmail,
		},
	})
	require.NoError(t, err)

	_ = repo
	commitHash = hash.String()
	return
}

func TestFetchBySubject(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	subj := &intoto.ResourceDescriptor{
		Digest: map[string]string{
			algoSHA1: commitHash,
		},
	}

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{}, []attestation.Subject{subj})
	require.NoError(t, err)
	require.Len(t, envs, 1)

	env := envs[0]
	require.NotNil(t, env.GetStatement())
	require.NotNil(t, env.GetPredicate())
	require.Equal(t, attestation.PredicateType(gspredicate.TypeV01), env.GetPredicate().GetType())

	// Subject should contain the commit hash.
	subjects := env.GetStatement().GetSubjects()
	require.Len(t, subjects, 1)
	require.Equal(t, commitHash, subjects[0].GetDigest()[algoSHA1])
}

func TestFetchBySubjectGitCommitAlgo(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	// Use gitCommit algorithm instead of sha1.
	subj := &intoto.ResourceDescriptor{
		Digest: map[string]string{
			intoto.AlgorithmGitCommit.String(): commitHash,
		},
	}

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{}, []attestation.Subject{subj})
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestFetchBySubjectNoMatch(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	// Subject with only sha256 — should return nothing.
	subj := &intoto.ResourceDescriptor{
		Digest: map[string]string{
			"sha256": "deadbeef",
		},
	}

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{}, []attestation.Subject{subj})
	require.NoError(t, err)
	require.Nil(t, envs)
}

func TestFetchBySubjectNonexistentCommit(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	subj := &intoto.ResourceDescriptor{
		Digest: map[string]string{
			algoSHA1: "0000000000000000000000000000000000000000",
		},
	}

	// Should return empty (commit doesn't exist, skipped via logrus.Debug).
	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{}, []attestation.Subject{subj})
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestFetchBySubjectMultipleCommits(t *testing.T) {
	repoPath := filepath.Join(t.TempDir(), "test-repo")
	repo, err := gogit.PlainInit(repoPath, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	commits := make([]string, 0, 3)
	for i := range 3 {
		testFile := filepath.Join(repoPath, fmt.Sprintf("file%d.txt", i))
		err = os.WriteFile(testFile, fmt.Appendf(nil, "content %d", i), 0o600)
		require.NoError(t, err)

		_, err = wt.Add(fmt.Sprintf("file%d.txt", i))
		require.NoError(t, err)

		hash, err := wt.Commit(fmt.Sprintf("Commit %d", i), &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  testName,
				Email: testEmail,
			},
		})
		require.NoError(t, err)
		commits = append(commits, hash.String())
	}

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	// Request all three commits at once.
	subjs := make([]attestation.Subject, 0, len(commits))
	for _, h := range commits {
		subjs = append(subjs, &intoto.ResourceDescriptor{
			Digest: map[string]string{algoSHA1: h},
		})
	}

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{}, subjs)
	require.NoError(t, err)
	require.Len(t, envs, 3)
}

func TestFetchNoop(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestFetchWithCommitInLocator(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	// Plain path doesn't parse as a vcslocator, so Fetch returns empty.
	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)

	// Use a file:// locator with the commit hash. This makes vcslocator
	// populate Components.Commit and Fetch will build a virtual attestation.
	c, err = New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@" + commitHash))
	require.NoError(t, err)

	envs, err = c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)

	env := envs[0]
	require.NotNil(t, env.GetStatement())
	subjects := env.GetStatement().GetSubjects()
	require.Len(t, subjects, 1)
	require.Equal(t, commitHash, subjects[0].GetDigest()[algoSHA1])
}

func TestNewRequiresPath(t *testing.T) {
	_, err := New()
	require.Error(t, err)
	require.Contains(t, err.Error(), "required")
}

func TestOpenRepoLocal(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	repo, err := c.openRepo(t.Context())
	require.NoError(t, err)
	require.NotNil(t, repo)
}

func TestOpenRepoFileLocator(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath))))
	require.NoError(t, err)

	repo, err := c.openRepo(t.Context())
	require.NoError(t, err)
	require.NotNil(t, repo)
}

func TestWithLimit(t *testing.T) {
	repoPath := filepath.Join(t.TempDir(), "test-repo")
	repo, err := gogit.PlainInit(repoPath, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	subjs := make([]attestation.Subject, 0, 3)
	for i := range 3 {
		testFile := filepath.Join(repoPath, fmt.Sprintf("file%d.txt", i))
		err = os.WriteFile(testFile, fmt.Appendf(nil, "content %d", i), 0o600)
		require.NoError(t, err)

		_, err = wt.Add(fmt.Sprintf("file%d.txt", i))
		require.NoError(t, err)

		hash, err := wt.Commit(fmt.Sprintf("Commit %d", i), &gogit.CommitOptions{
			Author: &object.Signature{
				Name:  testName,
				Email: testEmail,
			},
		})
		require.NoError(t, err)
		subjs = append(subjs, &intoto.ResourceDescriptor{
			Digest: map[string]string{algoSHA1: hash.String()},
		})
	}

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)

	envs, err := c.FetchBySubject(context.Background(), attestation.FetchOptions{Limit: 1}, subjs)
	require.NoError(t, err)
	require.Len(t, envs, 1)

	_ = repo
}

func TestSetKeys(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithRepoPath(repoPath))
	require.NoError(t, err)
	require.Empty(t, c.Keys)

	c.SetKeys(nil)
	require.Nil(t, c.Keys)
}

func TestFetchWithTagInLocator(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	repo, err := gogit.PlainOpen(repoPath)
	require.NoError(t, err)

	tagRef, err := repo.CreateTag("v1.0.0", plumbing.NewHash(commitHash), &gogit.CreateTagOptions{
		Tagger: &object.Signature{
			Name:  testName,
			Email: testEmail,
		},
		Message: "Release v1.0.0",
	})
	require.NoError(t, err)

	// Test both short tag name and full refs/tags/ format.
	for _, suffix := range []string{"v1.0.0", "refs/tags/v1.0.0"} {
		t.Run(suffix, func(t *testing.T) {
			c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@" + suffix))
			require.NoError(t, err)

			envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, envs, 1)

			env := envs[0]
			require.NotNil(t, env.GetStatement())
			require.NotNil(t, env.GetPredicate())

			// Tag locators produce a tag predicate, not a commit predicate.
			require.Equal(t, attestation.PredicateType("https://gitsign.sigstore.dev/predicate/tag/v0.1"), env.GetPredicate().GetType())

			// Subject should be the tag object hash, not the commit hash.
			subjects := env.GetStatement().GetSubjects()
			require.Len(t, subjects, 1)
			require.Equal(t, tagRef.Hash().String(), subjects[0].GetDigest()[algoSHA1])
			require.Equal(t, subjects[0].GetDigest()[algoSHA1], subjects[0].GetDigest()["gitTag"])
		})
	}
}

func TestFetchWithLightweightTagInLocator(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	// Create a lightweight tag pointing at the commit.
	repo, err := gogit.PlainOpen(repoPath)
	require.NoError(t, err)

	_, err = repo.CreateTag("v1.0.0", plumbing.NewHash(commitHash), nil)
	require.NoError(t, err)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@v1.0.0"))
	require.NoError(t, err)

	// Lightweight tags return an empty list (no attestable data).
	envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestFetchWithAnnotatedTagInLocator(t *testing.T) {
	repoPath, commitHash := initTestRepo(t)

	repo, err := gogit.PlainOpen(repoPath)
	require.NoError(t, err)

	tagRef, err := repo.CreateTag("v2.0.0", plumbing.NewHash(commitHash), &gogit.CreateTagOptions{
		Tagger: &object.Signature{
			Name:  testName,
			Email: testEmail,
		},
		Message: "Release v2.0.0",
	})
	require.NoError(t, err)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@v2.0.0"))
	require.NoError(t, err)

	envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)

	// Subject is the tag object hash, not the commit.
	subjects := envs[0].GetStatement().GetSubjects()
	require.Len(t, subjects, 1)
	require.Equal(t, tagRef.Hash().String(), subjects[0].GetDigest()[algoSHA1])
}

func TestFetchWithNonexistentTag(t *testing.T) {
	repoPath, _ := initTestRepo(t)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@v999.0.0"))
	require.NoError(t, err)

	envs, err := c.Fetch(context.Background(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)
}

// A commit's subject is named after the commit, not only its repository,
// and located with a VCS locator other tools resolve.
func TestNameCommit(t *testing.T) {
	t.Parallel()
	const sha = "26c86b565d84be21e02361ba939bbcbf19e39e33"
	for _, tc := range []struct {
		name     string
		remote   string
		digest   map[string]string
		wantName string
		wantURI  string
	}{
		{
			name:     "https remote",
			remote:   "https://github.com/policylabs/collector",
			wantName: "https://github.com/policylabs/collector@" + sha,
			wantURI:  "git+https://github.com/policylabs/collector@" + sha,
		},
		{
			name:     "the .git suffix is not part of a locator",
			remote:   "https://github.com/policylabs/collector.git",
			wantName: "https://github.com/policylabs/collector.git@" + sha,
			wantURI:  "git+https://github.com/policylabs/collector@" + sha,
		},
		{
			name:     "credentials in the remote are dropped",
			remote:   "https://x-access-token:" + "s3cret" + "@github.com/policylabs/collector",
			wantName: "https://github.com/policylabs/collector@" + sha,
			wantURI:  "git+https://github.com/policylabs/collector@" + sha,
		},
		{
			name:     "a port is kept",
			remote:   "https://git.example.com:8443/org/repo",
			wantName: "https://git.example.com:8443/org/repo@" + sha,
			wantURI:  "git+https://git.example.com:8443/org/repo@" + sha,
		},
		{
			name:     "plain http is located over https",
			remote:   "http://git.example.com/org/repo",
			wantName: "http://git.example.com/org/repo@" + sha,
			wantURI:  "git+https://git.example.com/org/repo@" + sha,
		},
		{
			name:     "ssh url",
			remote:   "ssh://git@github.com/policylabs/collector.git",
			wantName: "ssh://github.com/policylabs/collector.git@" + sha,
			wantURI:  "git+ssh://github.com/policylabs/collector@" + sha,
		},
		{
			name:     "scp-like remote",
			remote:   "git@github.com:policylabs/collector.git",
			wantName: "git@github.com:policylabs/collector.git@" + sha,
			wantURI:  "git+ssh://github.com/policylabs/collector@" + sha,
		},
		{
			name:     "local path",
			remote:   "/srv/git/collector",
			wantName: "/srv/git/collector@" + sha,
			wantURI:  "file:///srv/git/collector@" + sha,
		},
		{
			name:     "the digest may be under gitCommit only",
			remote:   "https://github.com/policylabs/collector",
			digest:   map[string]string{"gitCommit": sha},
			wantName: "https://github.com/policylabs/collector@" + sha,
			wantURI:  "git+https://github.com/policylabs/collector@" + sha,
		},
		{
			// No remote: nothing to locate the commit by.
			name: "no remote",
		},
		{
			name:     "no digest",
			remote:   "https://github.com/policylabs/collector",
			digest:   map[string]string{},
			wantName: "https://github.com/policylabs/collector",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			digest := tc.digest
			if digest == nil {
				digest = map[string]string{algoSHA1: sha}
			}
			subject := &intoto.ResourceDescriptor{Name: tc.remote, Digest: digest}
			nameCommit(subject)
			require.Equal(t, tc.wantName, subject.GetName())
			require.Equal(t, tc.wantURI, subject.GetUri())
		})
	}
}
