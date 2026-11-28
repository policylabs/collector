// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/envelope"
	gitpred "github.com/policylabs/collector/predicate/git"
	"github.com/policylabs/collector/repository"
)

// ofType returns the one attestation of a predicate type in a list.
func ofType(t *testing.T, envs []attestation.Envelope, pt attestation.PredicateType) attestation.Envelope {
	t.Helper()
	var found []attestation.Envelope
	for _, env := range envs {
		if env.GetStatement().GetPredicateType() == pt {
			found = append(found, env)
		}
	}
	require.Len(t, found, 1, pt)
	return found[0]
}

// requireRebuilds checks that the origin of an attestation describing a git
// object keeps that object, and that the attestation is rebuilt from it as
// it travels serialized.
func requireRebuilds(t *testing.T, original attestation.Envelope, algo, id string) {
	t.Helper()
	kept, ok := original.GetPredicate().GetOrigin().(*intoto.ResourceDescriptor)
	require.True(t, ok, "the attestation has no origin")
	data, err := protojson.Marshal(kept)
	require.NoError(t, err)
	origin := &intoto.ResourceDescriptor{}
	require.NoError(t, protojson.Unmarshal(data, origin))

	require.NotEmpty(t, origin.GetContent())
	require.Equal(t, map[string]string{algo: id}, origin.GetDigest())
	require.Nil(t, envelope.Parsers.ForMediaType(origin.GetMediaType()), "no envelope parser reads a git object")
	require.Equal(t, TypeMoniker, repository.Annotated(origin))

	rebuilt, err := Reassemble(t.Context(), origin, repository.ReassembleOptions{})
	require.NoError(t, err)
	require.Len(t, rebuilt, 1)
	require.Equal(t, original.GetStatement().GetPredicateType(), rebuilt[0].GetStatement().GetPredicateType())
	require.JSONEq(t, string(original.GetPredicate().GetData()), string(rebuilt[0].GetPredicate().GetData()))
	want, got := original.GetStatement().GetSubjects(), rebuilt[0].GetStatement().GetSubjects()
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].GetName(), got[i].GetName())
		require.Equal(t, want[i].GetDigest(), got[i].GetDigest())
	}
}

func TestKeepContentOfDescribedObjects(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	tagRef, err := repo.CreateTag("v1.0.0", head, &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "Tester", Email: "tester@example.com", When: time.Now()},
		Message: "Release v1.0.0\n",
	})
	require.NoError(t, err)

	c, err := New(WithLocator(path + "@v1.0.0"))
	require.NoError(t, err)

	plain, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)

	kept, err := c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, kept, len(plain))
	requireRebuilds(t, ofType(t, kept, gitpred.PredicateTypeCommit), "gitCommit", head.String())
	requireRebuilds(t, ofType(t, kept, gitpred.PredicateTypeTag), "gitTag", tagRef.Hash().String())

	// The attestations are built once and served to every fetch: one that
	// asks to keep content gets copies, and the ones served to the others
	// stay as they were.
	for _, envs := range [][]attestation.Envelope{plain, mustFetch(t, c)} {
		for _, pt := range []attestation.PredicateType{gitpred.PredicateTypeCommit, gitpred.PredicateTypeTag} {
			require.Nil(t, ofType(t, envs, pt).GetPredicate().GetOrigin(), pt)
		}
	}

	// By predicate type
	tags, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{KeepContent: true}, []attestation.PredicateType{gitpred.PredicateTypeTag})
	require.NoError(t, err)
	requireRebuilds(t, ofType(t, tags, gitpred.PredicateTypeTag), "gitTag", tagRef.Hash().String())
}

func mustFetch(t *testing.T, c *Collector) []attestation.Envelope {
	t.Helper()
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	return envs
}

// A commit fetched on demand for a subject query keeps its object too.
func TestKeepContentOfCommitFetchedBySubject(t *testing.T) {
	t.Parallel()
	path, head := fixtureRepo(t)
	repo, err := git.PlainOpen(path)
	require.NoError(t, err)
	headCommit, err := repo.CommitObject(head)
	require.NoError(t, err)
	parent := headCommit.ParentHashes[0].String()

	c, err := New(WithLocator(path))
	require.NoError(t, err)
	subject := []attestation.Subject{&intoto.ResourceDescriptor{Digest: map[string]string{"gitCommit": parent}}}

	res, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{KeepContent: true}, subject)
	require.NoError(t, err)
	require.Len(t, res, 1)
	requireRebuilds(t, res[0], "gitCommit", parent)

	res, err = c.FetchBySubject(t.Context(), attestation.FetchOptions{}, subject)
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Nil(t, res[0].GetPredicate().GetOrigin())
}
