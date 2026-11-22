// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/carabiner-dev/vcslocator"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"
)

// notesTree returns the paths of the notes in the repository's notes ref
// and, for each directory of the root tree, how many entries carry its
// name: more than one is a tree git refuses.
func notesTree(t *testing.T, repo *git.Repository) (files map[string]string, dirs map[string]int) {
	t.Helper()
	ref, err := repo.Reference(plumbing.ReferenceName(notesRef), true)
	require.NoError(t, err)
	commit, err := repo.CommitObject(ref.Hash())
	require.NoError(t, err)
	tree, err := commit.Tree()
	require.NoError(t, err)

	dirs = map[string]int{}
	for i := range tree.Entries {
		dirs[tree.Entries[i].Name]++
	}
	files = map[string]string{}
	walker := tree.Files()
	for {
		f, err := walker.Next()
		if err != nil {
			break
		}
		content, err := f.Contents()
		require.NoError(t, err)
		files[f.Name] = content
	}
	return files, dirs
}

// fsck runs git's own check of the repository's objects, the one a server
// applies to a push, when git is there to run it.
func fsck(t *testing.T, repoPath string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Log("git is not installed, skipping fsck")
		return
	}
	cmd := exec.CommandContext(t.Context(), "git", "fsck", "--strict", "--no-dangling")
	cmd.Dir = repoPath
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git fsck: %s", out)
	require.NotContains(t, string(out), "error", "git fsck: %s", out)
}

// storeNote stores one attestation in the note of sha.
func storeNote(t *testing.T, repoPath, sha string) {
	t.Helper()
	c, err := New(WithLocator(string(vcslocator.NewFromPath(repoPath))+"@"+sha), WithPush(false))
	require.NoError(t, err)
	require.NoError(t, c.Store(t.Context(), attestation.StoreOptions{}, []attestation.Envelope{createTestAttestation(t)}))
}

// shardedRepo returns a repository whose notes are sharded, with one note
// in the "ab" subtree for the commit it also returns.
func shardedRepo(t *testing.T) (repoPath string, repo *git.Repository, first string) {
	t.Helper()
	repoPath, _ = remoteWithCommits(t, 1)
	repo, err := git.PlainOpen(repoPath)
	require.NoError(t, err)

	first = "ab" + strings.Repeat("1", 38)
	c, err := New(WithLocator(string(vcslocator.NewFromPath(repoPath)) + "@" + first))
	require.NoError(t, err)
	require.NoError(t, c.updateNotesRef(repo, first[:2]+"/"+first[2:], []byte("{\"first\":true}\n"), first))
	return repoPath, repo, first
}

// The notes of two commits whose shas share their first two digits live in
// one subtree. Storing the second used to add a second subtree of the same
// name with that note alone in it: a tree with a duplicate entry, which a
// server refuses with "unpack index-pack failed". The more notes a
// repository had, the more of its commits could not be given one.
func TestStoreIntoAnExistingShard(t *testing.T) {
	repoPath, repo, first := shardedRepo(t)
	second := "ab" + strings.Repeat("2", 38)
	other := "cd" + strings.Repeat("3", 38)

	storeNote(t, repoPath, second)
	storeNote(t, repoPath, other)

	files, dirs := notesTree(t, repo)
	require.Equal(t, map[string]int{"ab": 1, "cd": 1}, dirs)
	require.Len(t, files, 3)
	require.JSONEq(t, `{"first":true}`, files["ab/"+first[2:]], "the note already in the subtree is kept")
	require.NotEmpty(t, files["ab/"+second[2:]])
	require.NotEmpty(t, files["cd/"+other[2:]])
	fsck(t, repoPath)
}

// Adding to a note that is already in a subtree keeps the subtree's other
// notes and the note's own earlier lines.
func TestStoreAppendsToAShardedNote(t *testing.T) {
	repoPath, repo, first := shardedRepo(t)
	second := "ab" + strings.Repeat("2", 38)
	storeNote(t, repoPath, second)

	storeNote(t, repoPath, first)
	storeNote(t, repoPath, second)

	files, dirs := notesTree(t, repo)
	require.Equal(t, map[string]int{"ab": 1}, dirs)
	require.Len(t, files, 2)
	require.Equal(t, 2, lines(files["ab/"+first[2:]]), "the line it had and the one added")
	require.True(t, strings.HasPrefix(files["ab/"+first[2:]], `{"first":true}`))
	require.Equal(t, 2, lines(files["ab/"+second[2:]]))
	fsck(t, repoPath)
}

// A note written at the root of the notes tree before the notes were
// sharded moves into its subtree when it is next written, and leaves no
// copy behind.
func TestStoreMovesARootNoteIntoItsShard(t *testing.T) {
	repoPath, _ := remoteWithCommits(t, 1)
	repo, err := git.PlainOpen(repoPath)
	require.NoError(t, err)

	// The first note of a repository is written at the root.
	early := "ef" + strings.Repeat("4", 38)
	storeNote(t, repoPath, early)
	files, _ := notesTree(t, repo)
	require.Contains(t, files, early)

	// Another writer shards the notes.
	c, err := New(WithLocator(string(vcslocator.NewFromPath(repoPath)) + "@" + early))
	require.NoError(t, err)
	sharded := "ef" + strings.Repeat("5", 38)
	require.NoError(t, c.updateNotesRef(repo, "ef/"+sharded[2:], []byte("{\"sharded\":true}\n"), sharded))

	storeNote(t, repoPath, early)

	files, dirs := notesTree(t, repo)
	require.Equal(t, map[string]int{"ef": 1}, dirs)
	require.Len(t, files, 2)
	require.Equal(t, 2, lines(files["ef/"+early[2:]]))
	require.JSONEq(t, `{"sharded":true}`, files["ef/"+sharded[2:]])
	fsck(t, repoPath)
}
