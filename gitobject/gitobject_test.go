// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitobject

import (
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/util"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/predicate/git"
)

const (
	releaseMessage = "Release v1.2.0\n\nCut by miniprow.\n\nEvaluated-Commit: deadbeef\nPull-Request: 7\n"
	commitMessage  = "Add the thing\n\nSigned-off-by: Tester <tester@example.com>\n"
)

// newRepo returns an in-memory repository with one commit and an annotated
// tag on it, both signed with signKey when it is not nil.
func newRepo(t *testing.T, signKey *key.GPGPrivate) (repo *gogit.Repository, commit, tag plumbing.Hash) {
	t.Helper()
	fs := memfs.New()
	repo, err := gogit.Init(memory.NewStorage(), fs)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{"https://github.com/example/repo"}})
	require.NoError(t, err)
	require.NoError(t, util.WriteFile(fs, "README.md", []byte("hi\n"), 0o644))
	wt, err := repo.Worktree()
	require.NoError(t, err)
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	sig := &object.Signature{Name: "Tester", Email: "tester@example.com", When: time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)}
	copts := &gogit.CommitOptions{Author: sig, Committer: sig}
	topts := &gogit.CreateTagOptions{Tagger: sig, Message: releaseMessage}
	if signKey != nil {
		copts.SignKey = signKey.Entity()
		topts.SignKey = signKey.Entity()
	}
	commit, err = wt.Commit(commitMessage, copts)
	require.NoError(t, err)
	ref, err := repo.CreateTag("v1.2.0", commit, topts)
	require.NoError(t, err)
	return repo, commit, ref.Hash()
}

func TestCommit(t *testing.T) {
	t.Parallel()
	repo, commit, _ := newRepo(t, nil)
	env, err := New().Commit(t.Context(), repo, commit)
	require.NoError(t, err)
	pred := env.GetPredicate()
	require.Equal(t, git.PredicateTypeCommit, pred.GetType())
	parsed, ok := pred.GetParsed().(*git.Commit)
	require.True(t, ok)
	require.Equal(t, commitMessage, parsed.Message)
	require.Equal(t, "Tester <tester@example.com>", parsed.Trailers.Get("Signed-off-by"))
	require.Empty(t, parsed.Parents)
	require.Equal(t, "tester@example.com", parsed.Committer.Email)
	require.Nil(t, pred.GetVerification(), "an unsigned commit has no verification")

	subjects := env.GetStatement().GetSubjects()
	require.Len(t, subjects, 2)
	require.Equal(t, "https://github.com/example/repo", subjects[0].GetName())
	require.Equal(t, commit.String(), subjects[0].GetDigest()["sha1"])
	require.Equal(t, commit.String(), subjects[0].GetDigest()["gitCommit"])
	require.Equal(t, map[string]string{"gitTree": parsed.Tree}, subjects[1].GetDigest())
	require.Equal(t, pred.GetData(), env.GetPredicate().GetData())
	require.Contains(t, string(pred.GetData()), `"tree":"`+parsed.Tree+`"`)
}

func TestTag(t *testing.T) {
	t.Parallel()
	repo, commit, tagHash := newRepo(t, nil)
	s := New()
	env, err := s.Tag(t.Context(), repo, tagHash)
	require.NoError(t, err)
	pred := env.GetPredicate()
	require.Equal(t, git.PredicateTypeTag, pred.GetType())
	parsed, ok := pred.GetParsed().(*git.Tag)
	require.True(t, ok)
	require.Equal(t, "v1.2.0", parsed.Name)
	require.Equal(t, commit.String(), parsed.Object)
	require.Equal(t, "commit", parsed.ObjectType)
	require.Equal(t, "7", parsed.Trailers.Get("Pull-Request"))
	require.Equal(t, "deadbeef", parsed.Trailers.Get("Evaluated-Commit"))

	subjects := env.GetStatement().GetSubjects()
	require.Len(t, subjects, 2)
	require.Equal(t, tagHash.String(), subjects[0].GetDigest()["gitTag"])
	require.Equal(t, commit.String(), subjects[1].GetDigest()["gitCommit"])

	byName, err := s.TagNamed(t.Context(), repo, "v1.2.0")
	require.NoError(t, err)
	require.Equal(t, env.GetPredicate().GetData(), byName.GetPredicate().GetData())
	byRef, err := s.TagNamed(t.Context(), repo, "refs/tags/v1.2.0")
	require.NoError(t, err)
	require.Equal(t, env.GetPredicate().GetData(), byRef.GetPredicate().GetData())
}

func TestTagNamedLightweight(t *testing.T) {
	t.Parallel()
	repo, commit, _ := newRepo(t, nil)
	_, err := repo.CreateTag("light", commit, nil)
	require.NoError(t, err)
	_, err = New().TagNamed(t.Context(), repo, "light")
	require.ErrorIs(t, err, ErrLightweightTag)
}

func TestSignedObjectsVerify(t *testing.T) {
	t.Parallel()
	priv, err := key.NewGenerator().GenerateGPGKeyPair()
	require.NoError(t, err)
	repo, commit, tagHash := newRepo(t, priv)

	// Without the key nothing is established.
	env, err := New().Commit(t.Context(), repo, commit)
	require.NoError(t, err)
	require.Nil(t, env.GetPredicate().GetVerification())

	s := New(WithKeys(priv.GPGPublicKey()))
	env, err = s.Commit(t.Context(), repo, commit)
	require.NoError(t, err)
	v, ok := env.GetPredicate().GetVerification().(*sapi.Verification)
	require.True(t, ok, "a commit signed with a configured key verifies")
	require.True(t, v.GetSignature().GetVerified())
	require.Len(t, v.GetSignature().GetIdentities(), 1)
	require.NotNil(t, v.GetSignature().GetIdentities()[0].GetKey())

	env, err = s.Tag(t.Context(), repo, tagHash)
	require.NoError(t, err)
	require.NotNil(t, env.GetPredicate().GetVerification(), "a tag signed with a configured key verifies")

	// SetKeys replaces the configured keys.
	s.SetKeys(nil)
	env, err = s.Commit(t.Context(), repo, commit)
	require.NoError(t, err)
	require.Nil(t, env.GetPredicate().GetVerification())
}

func TestBuiltinKeysAreGitHubs(t *testing.T) {
	t.Parallel()
	keys, err := BuiltinKeys()
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	for _, k := range keys {
		pub, ok := k.(*key.GPGPublic)
		require.True(t, ok)
		require.Contains(t, pub.UserIDs()[0], "noreply@github.com")
	}
	require.Empty(t, NewVerifier().Keys(), "built-in keys are not among the configured ones")
}
