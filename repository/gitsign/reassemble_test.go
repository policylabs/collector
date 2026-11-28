// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package gitsign

import (
	"crypto/sha1" //nolint:gosec // git object ids are sha1
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/carabiner-dev/vcslocator"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
)

const testRemoteURL = "https://example.com/org/repo"

// travelled returns the origin of an attestation as it reads after
// travelling serialized, in the results of an evaluation.
func travelled(t *testing.T, env attestation.Envelope) *intoto.ResourceDescriptor {
	t.Helper()
	kept, ok := env.GetPredicate().GetOrigin().(*intoto.ResourceDescriptor)
	require.True(t, ok)
	data, err := protojson.Marshal(kept)
	require.NoError(t, err)
	origin := &intoto.ResourceDescriptor{}
	require.NoError(t, protojson.Unmarshal(data, origin))
	return origin
}

// gitObjectID hashes the content of a git object the way git does.
func gitObjectID(objType string, content []byte) string {
	data := append([]byte(fmt.Sprintf("%s %d\x00", objType, len(content))), content...)
	sum := sha1.Sum(data) //nolint:gosec // git object ids are sha1
	return hex.EncodeToString(sum[:])
}

// requireSameStatement checks a rebuilt attestation says what the original did.
func requireSameStatement(t *testing.T, original, rebuilt attestation.Envelope) {
	t.Helper()
	require.Equal(t, original.GetPredicate().GetType(), rebuilt.GetPredicate().GetType())
	require.JSONEq(t, string(original.GetPredicate().GetData()), string(rebuilt.GetPredicate().GetData()))
	want, got := original.GetStatement().GetSubjects(), rebuilt.GetStatement().GetSubjects()
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].GetName(), got[i].GetName())
		require.Equal(t, want[i].GetUri(), got[i].GetUri())
		require.Equal(t, want[i].GetDigest(), got[i].GetDigest())
	}
}

func TestReassembleCommit(t *testing.T) {
	t.Parallel()
	repoPath, commitHash := initTestRepo(t)
	repo, err := gogit.PlainOpen(repoPath)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{testRemoteURL}})
	require.NoError(t, err)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@" + commitHash))
	require.NoError(t, err)

	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.Nil(t, envelope.OriginContent(envs[0].GetPredicate()), "content is not kept unless asked")

	envs, err = c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	original := envs[0]
	origin := travelled(t, original)

	// What is kept is the commit as git stores it: hashing it as git does
	// gives the id the origin carries as its digest.
	require.Equal(t, map[string]string{"gitCommit": commitHash}, origin.GetDigest())
	require.Equal(t, commitHash, gitObjectID("commit", origin.GetContent()))

	// No envelope parser reads it: the origin names this repository type
	require.Empty(t, origin.GetMediaType())
	require.Nil(t, envelope.Parsers.ForMediaType(origin.GetMediaType()))
	require.Equal(t, TypeMoniker, repository.Annotated(origin))

	rebuilt, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	requireSameStatement(t, original, rebuilt[0])
	require.Equal(t, testRemoteURL+"@"+commitHash, rebuilt[0].GetStatement().GetSubjects()[0].GetName())

	// FetchBySubject keeps the object too
	envs, err = c.FetchBySubject(t.Context(), attestation.FetchOptions{KeepContent: true}, []attestation.Subject{
		&intoto.ResourceDescriptor{Digest: map[string]string{"gitCommit": commitHash}},
	})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.Equal(t, origin.GetContent(), envelope.OriginContent(envs[0].GetPredicate()))
}

func TestReassembleTag(t *testing.T) {
	t.Parallel()
	repoPath, commitHash := initTestRepo(t)
	repo, err := gogit.PlainOpen(repoPath)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{testRemoteURL}})
	require.NoError(t, err)
	tagRef, err := repo.CreateTag("v2.0.0", plumbing.NewHash(commitHash), &gogit.CreateTagOptions{
		Tagger:  &object.Signature{Name: testName, Email: testEmail},
		Message: "Release v2.0.0",
	})
	require.NoError(t, err)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@v2.0.0"))
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	original := envs[0]
	origin := travelled(t, original)

	// The object kept is the tag, not the commit it points to
	tagHash := tagRef.Hash().String()
	require.Equal(t, map[string]string{"gitTag": tagHash}, origin.GetDigest())
	require.Equal(t, tagHash, gitObjectID("tag", origin.GetContent()))

	rebuilt, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	requireSameStatement(t, original, rebuilt[0])
	require.Equal(t, testRemoteURL, rebuilt[0].GetStatement().GetSubjects()[0].GetName())
}

func TestReassembleErrors(t *testing.T) {
	t.Parallel()
	repoPath, commitHash := initTestRepo(t)
	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath)) + "@" + commitHash))
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	kept := travelled(t, envs[0])

	t.Run("no-material", func(t *testing.T) {
		t.Parallel()
		_, err := Reassemble(t.Context(), &intoto.ResourceDescriptor{Content: kept.GetContent()}, repository.ReassembleOptions{})
		require.ErrorContains(t, err, "no reassembly material")
	})
	t.Run("not-a-commit-or-tag", func(t *testing.T) {
		t.Parallel()
		origin := &intoto.ResourceDescriptor{Content: kept.GetContent()}
		require.NoError(t, repository.Annotate(origin, TypeMoniker, map[string]any{materialObject: "blob"}))
		_, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
		require.ErrorContains(t, err, "no commit or tag")
	})
	// Content that is not the object the origin says it is, is refused
	t.Run("tampered-content", func(t *testing.T) {
		t.Parallel()
		origin := travelled(t, envs[0])
		origin.Content = append([]byte{}, origin.GetContent()...)
		origin.Content = append(origin.Content, '\n')
		_, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
		require.ErrorContains(t, err, "as its origin says")
	})
	t.Run("tag-without-name", func(t *testing.T) {
		t.Parallel()
		origin := &intoto.ResourceDescriptor{Content: []byte("object 0000000000000000000000000000000000000000\ntype commit\ntag v1\n\nmsg\n")}
		origin.Digest = map[string]string{"gitTag": gitObjectID("tag", origin.GetContent())}
		require.NoError(t, repository.Annotate(origin, TypeMoniker, map[string]any{materialObject: "tag"}))
		_, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
		require.ErrorContains(t, err, "names no tag")
	})
}

// A commit signed with a key verifies again when the key comes in the
// options, as it did when the repository was configured with it.
func TestReassembleKeySigned(t *testing.T) {
	t.Parallel()
	priv, err := key.NewGenerator().GenerateGPGKeyPair()
	require.NoError(t, err)
	keys := []key.PublicKeyProvider{priv.GPGPublicKey()}

	repoPath := filepath.Join(t.TempDir(), "signed-repo")
	repo, err := gogit.PlainInit(repoPath, false)
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoPath, "file.txt"), []byte("content"), 0o600))
	_, err = wt.Add("file.txt")
	require.NoError(t, err)
	hash, err := wt.Commit("Signed commit", &gogit.CommitOptions{
		Author:  &object.Signature{Name: testName, Email: testEmail},
		SignKey: priv.Entity(),
	})
	require.NoError(t, err)

	c, err := New(WithInitString(string(vcslocator.NewFromPath(repoPath))+"@"+hash.String()), WithKeys(keys...))
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	original := envs[0]
	require.NotNil(t, original.GetVerification())
	require.True(t, original.GetVerification().GetVerified())
	origin := travelled(t, original)

	identity := func(e attestation.Envelope) string {
		sv, ok := e.GetVerification().(*sapi.Verification)
		require.True(t, ok)
		ids := sv.GetSignature().GetIdentities()
		require.Len(t, ids, 1)
		return ids[0].GetKey().GetId()
	}

	rebuilt, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{Keys: keys})
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	requireSameStatement(t, original, rebuilt[0])
	require.NotNil(t, rebuilt[0].GetVerification())
	require.True(t, rebuilt[0].GetVerification().GetVerified())
	require.Equal(t, identity(original), identity(rebuilt[0]))

	// Without the key the attestation is rebuilt, but nothing is
	// established about who signed the commit.
	rebuilt, err = Reassemble(t.Context(), origin, repository.ReassembleOptions{})
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	requireSameStatement(t, original, rebuilt[0])
	require.Nil(t, rebuilt[0].GetVerification())
}
