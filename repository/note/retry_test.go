// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/carabiner-dev/vcslocator"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"
)

// remoteWithCommits creates a repository on disk to stand for the remote,
// with n commits, and returns its path and the commits.
func remoteWithCommits(t *testing.T, n int) (string, []plumbing.Hash) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "remote")
	repo, err := git.PlainInit(path, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	commits := make([]plumbing.Hash, 0, n)
	for i := range n {
		name := "file" + string(rune('a'+i)) + ".txt"
		require.NoError(t, os.WriteFile(filepath.Join(path, name), []byte(name), 0o600))
		_, err = wt.Add(name)
		require.NoError(t, err)
		hash, err := wt.Commit("commit "+name, &git.CommitOptions{
			Author: &object.Signature{Name: "Carabiner Test Robot", Email: "bot@carabiner.dev", When: time.Now()},
		})
		require.NoError(t, err)
		commits = append(commits, hash)
	}
	return path, commits
}

// cloneForNotes clones the remote to memory and fetches its notes, as Store
// does for a repository it reaches over the network.
func cloneForNotes(t *testing.T, remote string) *git.Repository {
	t.Helper()
	repo, err := git.Clone(memory.NewStorage(), nil, &git.CloneOptions{URL: remote})
	require.NoError(t, err)
	err = repo.Fetch(&git.FetchOptions{RefSpecs: []config.RefSpec{"+" + notesRef + ":" + notesRef}})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) && !errors.Is(err, git.NoMatchingRefSpecError{}) {
		require.NoError(t, err)
	}
	return repo
}

// storeOnRemote writes a note straight into the remote repository: another
// writer, getting there first.
func storeOnRemote(t *testing.T, remote string, commit plumbing.Hash) {
	t.Helper()
	other, err := New(WithLocator(string(vcslocator.NewFromPath(remote))+"@"+commit.String()), WithPush(false))
	require.NoError(t, err)
	require.NoError(t, other.Store(t.Context(), attestation.StoreOptions{}, []attestation.Envelope{createTestAttestation(t)}))
}

// noteOf returns the note the remote holds for a commit, "" when none.
func noteOf(t *testing.T, remote string, commit plumbing.Hash) string {
	t.Helper()
	repo, err := git.PlainOpen(remote)
	require.NoError(t, err)
	ref, err := repo.Reference(plumbing.ReferenceName(notesRef), true)
	if err != nil {
		return ""
	}
	c, err := repo.CommitObject(ref.Hash())
	require.NoError(t, err)
	tree, err := c.Tree()
	require.NoError(t, err)
	sha := commit.String()
	for _, path := range []string{sha, sha[:2] + "/" + sha[2:]} {
		if f, err := tree.File(path); err == nil {
			content, err := f.Contents()
			require.NoError(t, err)
			return content
		}
	}
	return ""
}

// lines counts the attestations of a note: one per non-empty line.
func lines(note string) int {
	n := 0
	for _, l := range strings.Split(note, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

// fastRetries makes the retries of a test wait a millisecond.
func fastRetries(t *testing.T) {
	t.Helper()
	was := pushRetryDelay
	pushRetryDelay = time.Millisecond
	t.Cleanup(func() { pushRetryDelay = was })
}

// Every note of a repository lives under one ref, so a writer that read the
// notes before another one pushed is rejected. It reads them again, writes
// its note on top and pushes that: both notes end up on the remote, and its
// own is there once.
func TestStoreRetriesARejectedPush(t *testing.T) {
	fastRetries(t)
	remote, commits := remoteWithCommits(t, 2)
	ours, theirs := commits[0], commits[1]

	// Two clones taken before the other writer lands: both are stale.
	giveUp, tryAgain := cloneForNotes(t, remote), cloneForNotes(t, remote)
	storeOnRemote(t, remote, theirs)

	c, err := New(WithLocator(string(vcslocator.NewFromPath(remote)) + "@" + ours.String()))
	require.NoError(t, err)
	envs := []attestation.Envelope{createTestAttestation(t)}

	// Without retrying, the push is refused and the remote is left alone.
	err = c.storeInRepo(t.Context(), giveUp, ours.String(), envs, true, false)
	require.ErrorContains(t, err, "pushing notes")
	require.Empty(t, noteOf(t, remote, ours))

	err = c.storeInRepo(t.Context(), tryAgain, ours.String(), envs, true, true)
	require.NoError(t, err)
	require.Equal(t, 1, lines(noteOf(t, remote, ours)), "our note, once")
	require.Equal(t, 1, lines(noteOf(t, remote, theirs)), "the other writer's note is kept")
}

// A writer whose very first note races with another's has no local notes
// to go back to: the remote's become its starting point.
func TestStoreRetriesWhenTheRemoteHadNoNotes(t *testing.T) {
	fastRetries(t)
	remote, commits := remoteWithCommits(t, 3)

	// Two stale clones, neither having seen any note.
	first, second := cloneForNotes(t, remote), cloneForNotes(t, remote)
	envs := []attestation.Envelope{createTestAttestation(t)}
	for i, clone := range []*git.Repository{first, second} {
		c, err := New(WithLocator(string(vcslocator.NewFromPath(remote)) + "@" + commits[i].String()))
		require.NoError(t, err)
		require.NoError(t, c.storeInRepo(t.Context(), clone, commits[i].String(), envs, true, true))
	}
	require.Equal(t, 1, lines(noteOf(t, remote, commits[0])))
	require.Equal(t, 1, lines(noteOf(t, remote, commits[1])))
	require.Empty(t, noteOf(t, remote, commits[2]))
}

func TestRetryablePush(t *testing.T) {
	t.Parallel()
	for _, err := range []error{
		errors.New("malformed unpack status: unpack index-pack failed"),
		git.ErrNonFastForwardUpdate,
		errors.New("connection reset by peer"),
	} {
		require.True(t, retryablePush(t.Context(), err), err)
	}
	for _, err := range []error{
		transport.ErrAuthenticationRequired,
		transport.ErrAuthorizationFailed,
		transport.ErrRepositoryNotFound,
	} {
		require.False(t, retryablePush(t.Context(), err), err)
	}
	// Nothing is retried under a context that is done.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.False(t, retryablePush(ctx, errors.New("connection reset by peer")))
}
