// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitobject synthesizes attestations from git objects. Given a
// repository and a commit or an annotated tag, it returns an in-toto
// statement whose predicate is the object's content (the predicate/git
// types) and whose subjects are what the object's bytes prove: a commit
// proves its own sha and names its tree, a tag proves its own sha and
// names its target. Nothing is stored and nothing is signed: the envelope
// is virtual, and its verification is the object's own signature, checked
// against the configured PGP keys and GitHub's web-flow key, so a merge or
// squash commit GitHub made verifies as GitHub's with no configuration.
//
// Sigstore (gitsign) signatures are not verified here: the gitsign driver
// is the authority for those and already describes the commits it signs.
//
// The package is a library, not a driver. Every git-related driver that
// wants to describe the objects it reads uses it, so a verifier sees the
// same commit and tag attestations whichever driver served them.
package gitobject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"

	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/predicate/git"
	intotostatement "github.com/policylabs/collector/statement/intoto"
)

// ErrLightweightTag is returned when a tag name resolves to a commit rather
// than to a tag object: a lightweight tag has no object to attest.
var ErrLightweightTag = errors.New("tag is lightweight, it has no tag object")

// Synthesizer builds attestations from git objects.
type Synthesizer struct {
	verifier *Verifier
	remote   string
}

// Option configures a Synthesizer.
type Option func(*Synthesizer)

// WithRemote names the remote whose URL names the subjects (default
// "origin"). A repository without that remote yields unnamed subjects.
func WithRemote(name string) Option {
	return func(s *Synthesizer) { s.remote = name }
}

// WithKeys adds PGP keys the object signatures are verified against, on top
// of the keys the package ships with.
func WithKeys(keys ...key.PublicKeyProvider) Option {
	return func(s *Synthesizer) { s.verifier.AddKeys(keys...) }
}

// New returns a Synthesizer.
func New(opts ...Option) *Synthesizer {
	s := &Synthesizer{verifier: NewVerifier(), remote: "origin"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// SetKeys replaces the configured PGP keys (the shipped keys stay). It
// implements repository.SignatureVerifier so a driver can forward the keys
// it is handed.
func (s *Synthesizer) SetKeys(keys []key.PublicKeyProvider) {
	s.verifier.SetKeys(keys)
}

// Verifier returns the signature verifier the synthesizer uses.
func (s *Synthesizer) Verifier() *Verifier { return s.verifier }

// Commit returns the attestation describing a commit. Its subjects are the
// commit (sha1 and gitCommit digests) and its tree (gitTree digest).
func (s *Synthesizer) Commit(ctx context.Context, repo *gogit.Repository, hash plumbing.Hash) (attestation.Envelope, error) {
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("reading commit %s: %w", hash, err)
	}
	pred := &git.Commit{
		Tree:      commit.TreeHash.String(),
		Author:    identity(commit.Author),
		Committer: identity(commit.Committer),
		Message:   commit.Message,
		Trailers:  git.ParseTrailers(commit.Message),
	}
	for _, p := range commit.ParentHashes {
		pred.Parents = append(pred.Parents, p.String())
	}
	name := s.subjectName(repo)
	subjects := []*intoto.ResourceDescriptor{
		{
			Name: name,
			Digest: map[string]string{
				string(intoto.AlgorithmSHA1):      commit.Hash.String(),
				string(intoto.AlgorithmGitCommit): commit.Hash.String(),
			},
		},
		{
			Digest: map[string]string{string(intoto.AlgorithmGitTree): commit.TreeHash.String()},
		},
	}
	return s.envelope(ctx, git.PredicateTypeCommit, pred, subjects, commit, commit.PGPSignature)
}

// Tag returns the attestation describing an annotated tag object. Its
// subjects are the tag object (sha1 and gitTag digests) and its target
// (sha1 and the digest named after the target's type).
func (s *Synthesizer) Tag(ctx context.Context, repo *gogit.Repository, hash plumbing.Hash) (attestation.Envelope, error) {
	tag, err := repo.TagObject(hash)
	if err != nil {
		return nil, fmt.Errorf("reading tag %s: %w", hash, err)
	}
	pred := &git.Tag{
		Object:     tag.Target.String(),
		ObjectType: tag.TargetType.String(),
		Name:       tag.Name,
		Tagger:     identity(tag.Tagger),
		Message:    tag.Message,
		Trailers:   git.ParseTrailers(tag.Message),
	}
	subjects := []*intoto.ResourceDescriptor{
		{
			Name: s.subjectName(repo),
			Digest: map[string]string{
				string(intoto.AlgorithmSHA1):   tag.Hash.String(),
				string(intoto.AlgorithmGitTag): tag.Hash.String(),
			},
		},
		{
			Digest: map[string]string{
				string(intoto.AlgorithmSHA1):            tag.Target.String(),
				string(targetAlgorithm(tag.TargetType)): tag.Target.String(),
			},
		},
	}
	return s.envelope(ctx, git.PredicateTypeTag, pred, subjects, tag, tag.PGPSignature)
}

// TagNamed returns the attestation describing the annotated tag of that
// name (with or without refs/tags/). A lightweight tag is ErrLightweightTag.
func (s *Synthesizer) TagNamed(ctx context.Context, repo *gogit.Repository, name string) (attestation.Envelope, error) {
	ref, err := repo.Reference(plumbing.NewTagReferenceName(plumbing.ReferenceName(name).Short()), true)
	if err != nil {
		return nil, fmt.Errorf("resolving tag %q: %w", name, err)
	}
	if _, err := repo.TagObject(ref.Hash()); errors.Is(err, plumbing.ErrObjectNotFound) {
		return nil, fmt.Errorf("%s: %w", name, ErrLightweightTag)
	}
	return s.Tag(ctx, repo, ref.Hash())
}

// envelope wraps a predicate and its subjects in a virtual envelope, with
// the object's signature verification when one of the keys verifies it.
func (s *Synthesizer) envelope(
	ctx context.Context, ptype attestation.PredicateType, parsed any,
	subjects []*intoto.ResourceDescriptor, obj signedObject, signature string,
) (attestation.Envelope, error) {
	data, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}
	pred := &generic.Predicate{Type: ptype, Parsed: parsed, Data: data}
	if v := s.verifier.Verify(ctx, obj, signature); v != nil {
		pred.SetVerification(v)
	}
	return NewEnvelope(intotostatement.NewStatement(
		intotostatement.WithPredicate(pred),
		intotostatement.WithSubject(subjects...),
	)), nil
}

// subjectName is the URL of the configured remote, or "" without one.
func (s *Synthesizer) subjectName(repo *gogit.Repository) string {
	if s.remote == "" {
		return ""
	}
	remote, err := repo.Remote(s.remote)
	if err != nil || len(remote.Config().URLs) == 0 {
		return ""
	}
	return remote.Config().URLs[0]
}

func identity(sig object.Signature) *git.Identity {
	if sig.Name == "" && sig.Email == "" && sig.When.IsZero() {
		return nil
	}
	return &git.Identity{Name: sig.Name, Email: sig.Email, Date: sig.When.UTC()}
}

// targetAlgorithms are the in-toto digest algorithms naming git object types.
var targetAlgorithms = map[plumbing.ObjectType]intoto.HashAlgorithm{
	plumbing.CommitObject: intoto.AlgorithmGitCommit,
	plumbing.TagObject:    intoto.AlgorithmGitTag,
	plumbing.TreeObject:   intoto.AlgorithmGitTree,
	plumbing.BlobObject:   intoto.AlgorithmGitBlob,
}

// targetAlgorithm is the in-toto digest algorithm naming a git object type,
// sha1 for anything else.
func targetAlgorithm(t plumbing.ObjectType) intoto.HashAlgorithm {
	if algo, ok := targetAlgorithms[t]; ok {
		return algo
	}
	return intoto.AlgorithmSHA1
}
