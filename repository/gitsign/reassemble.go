// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package gitsign

import (
	"context"
	"errors"
	"fmt"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/gitobject"
	"github.com/policylabs/collector/repository"
)

// materialTag is the key of the reassembly material holding the name of the
// tag, for tag objects: the statement is built from the tag reference. The
// rest of the material is what gitobject records with any kept git object.
const materialTag = "tag"

// keepObject records the git object an attestation was synthesized from as
// the origin of its predicate (see gitobject.ObjectOrigin): the object as
// git stores it, with its own id as the digest, and this repository type
// named to build the attestation again from it (see Reassemble).
func (c *Collector) keepObject(repo *gogit.Repository, env attestation.Envelope, objType plumbing.ObjectType, hash plumbing.Hash, tagName string) error {
	if env == nil || env.GetPredicate() == nil {
		return errors.New("attestation has no predicate")
	}
	extra := map[string]any{}
	if tagName != "" {
		extra[materialTag] = tagName
	}
	origin, err := gitobject.ObjectOrigin(repo, objType, hash, TypeMoniker, c.Options.Remote, extra)
	if err != nil {
		return err
	}
	// The subject of a commit is located (see nameCommit): the origin is
	// that same object.
	if subjects := env.GetStatement().GetSubjects(); len(subjects) > 0 {
		origin.Uri = subjects[0].GetUri()
	}
	env.GetPredicate().SetOrigin(origin)
	return nil
}

// Reassemble rebuilds the attestation kept in an origin by this repository
// type: the one synthesized from a git commit or tag. The object is put in a
// repository of its own, in memory, with the remote the subject was named
// after, and the attestation is built from it as it was the first time.
//
// The signature of the object is verified again, which is what gives the
// attestation its verification. A sigstore signature that does not embed its
// transparency log entry is looked up in the public log, as when first read;
// a signature made with a key verifies against the keys in the options and
// the built-in ones.
func Reassemble(ctx context.Context, origin *intoto.ResourceDescriptor, opts repository.ReassembleOptions) ([]attestation.Envelope, error) {
	restored, err := gitobject.RestoreObject(origin)
	if err != nil {
		return nil, err
	}

	c := &Collector{
		Options:  Options{Remote: restored.Remote, RekorURL: defaultRekorURL},
		Keys:     opts.Keys,
		verifier: gitobject.NewVerifier(gitobject.WithRekorURL(defaultRekorURL)),
	}
	c.verifier.SetKeys(opts.Keys)

	var env attestation.Envelope
	if restored.Type == plumbing.TagObject {
		tagName, _ := restored.Material[materialTag].(string) //nolint:errcheck // an absent or odd value reads as empty
		if tagName == "" {
			return nil, errors.New("reassembly material names no tag")
		}
		ref := plumbing.NewHashReference(plumbing.NewTagReferenceName(tagName), restored.Hash)
		if err := restored.Repo.Storer.SetReference(ref); err != nil {
			return nil, fmt.Errorf("creating tag: %w", err)
		}
		env, err = c.buildVirtualTagAttestation(ctx, restored.Repo, tagName)
	} else {
		env, err = c.buildVirtualAttestation(ctx, restored.Repo, restored.Hash.String())
	}
	if err != nil {
		return nil, err
	}
	return []attestation.Envelope{env}, nil
}
