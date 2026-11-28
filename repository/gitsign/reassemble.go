// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package gitsign

import (
	"context"
	"errors"
	"fmt"
	"io"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/gitobject"
	"github.com/policylabs/collector/repository"
)

// Keys of the reassembly material recorded with a kept git object: what the
// attestation is built from that the object itself does not hold.
const (
	// materialObject is the type of the object kept: commit or tag.
	materialObject = "object"
	// materialRemote is the name of the remote the subject is named after
	// and materialURL its URL, empty when the repository had no such remote.
	materialRemote = "remote"
	materialURL    = "url"
	// materialTag is the name of the tag, for tag objects.
	materialTag = "tag"
)

// keepObject records the git object an attestation was synthesized from as
// the origin of its predicate.
//
// The content is the object as git stores it, signature included, and the
// digest of the origin is the object's own id (gitCommit or gitTag): hashing
// the content the way git does gives it back. It has no media type, as no
// envelope parser reads it. The origin names this repository type instead,
// which builds the attestation again from the object (see Reassemble).
func (c *Collector) keepObject(repo *gogit.Repository, env attestation.Envelope, objType plumbing.ObjectType, hash plumbing.Hash, tagName string) error {
	if env == nil || env.GetPredicate() == nil {
		return errors.New("attestation has no predicate")
	}
	obj, err := repo.Storer.EncodedObject(objType, hash)
	if err != nil {
		return fmt.Errorf("reading %s %s: %w", objType, hash, err)
	}
	reader, err := obj.Reader()
	if err != nil {
		return fmt.Errorf("opening %s %s: %w", objType, hash, err)
	}
	defer reader.Close() //nolint:errcheck
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading %s %s: %w", objType, hash, err)
	}

	algo := intoto.AlgorithmGitCommit.String()
	if objType == plumbing.TagObject {
		algo = intoto.AlgorithmGitTag.String()
	}
	origin := &intoto.ResourceDescriptor{
		Name:    hash.String(),
		Digest:  map[string]string{algo: hash.String()},
		Content: data,
	}
	// The subject of a commit is located (see nameCommit): the origin is
	// that same object.
	if subjects := env.GetStatement().GetSubjects(); len(subjects) > 0 {
		origin.Uri = subjects[0].GetUri()
	}

	material := map[string]any{
		materialObject: objType.String(),
		materialRemote: c.Options.Remote,
	}
	if remote, err := repo.Remote(c.Options.Remote); err == nil && remote.Config() != nil && len(remote.Config().URLs) > 0 {
		material[materialURL] = remote.Config().URLs[0]
	}
	if tagName != "" {
		material[materialTag] = tagName
	}
	if err := repository.Annotate(origin, TypeMoniker, material); err != nil {
		return err
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
	material := repository.Material(origin)
	if material == nil {
		return nil, errors.New("origin has no reassembly material")
	}
	str := func(k string) string {
		s, _ := material[k].(string) //nolint:errcheck // an absent or odd value reads as empty
		return s
	}

	objType, err := plumbing.ParseObjectType(str(materialObject))
	if err != nil || (objType != plumbing.CommitObject && objType != plumbing.TagObject) {
		return nil, fmt.Errorf("reassembly material names no commit or tag (%q)", str(materialObject))
	}

	repo, err := gogit.Init(memory.NewStorage(), nil)
	if err != nil {
		return nil, fmt.Errorf("creating repository: %w", err)
	}
	obj := repo.Storer.NewEncodedObject()
	obj.SetType(objType)
	w, err := obj.Writer()
	if err != nil {
		return nil, fmt.Errorf("writing %s: %w", objType, err)
	}
	if _, err := w.Write(origin.GetContent()); err != nil {
		return nil, fmt.Errorf("writing %s: %w", objType, err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("writing %s: %w", objType, err)
	}
	hash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		return nil, fmt.Errorf("storing %s: %w", objType, err)
	}

	// The content has to be the object the origin says it is
	algo := intoto.AlgorithmGitCommit.String()
	if objType == plumbing.TagObject {
		algo = intoto.AlgorithmGitTag.String()
	}
	if want := origin.GetDigest()[algo]; want != hash.String() {
		return nil, fmt.Errorf("kept %s is %s, not %s as its origin says", objType, hash, want)
	}

	remote := str(materialRemote)
	if url := str(materialURL); url != "" && remote != "" {
		if _, err := repo.CreateRemote(&config.RemoteConfig{Name: remote, URLs: []string{url}}); err != nil {
			return nil, fmt.Errorf("creating remote: %w", err)
		}
	}

	c := &Collector{
		Options:  Options{Remote: remote, RekorURL: defaultRekorURL},
		Keys:     opts.Keys,
		verifier: gitobject.NewVerifier(gitobject.WithRekorURL(defaultRekorURL)),
	}
	c.verifier.SetKeys(opts.Keys)

	var env attestation.Envelope
	if objType == plumbing.TagObject {
		tagName := str(materialTag)
		if tagName == "" {
			return nil, errors.New("reassembly material names no tag")
		}
		ref := plumbing.NewHashReference(plumbing.NewTagReferenceName(tagName), hash)
		if err := repo.Storer.SetReference(ref); err != nil {
			return nil, fmt.Errorf("creating tag: %w", err)
		}
		env, err = c.buildVirtualTagAttestation(ctx, repo, tagName)
	} else {
		env, err = c.buildVirtualAttestation(ctx, repo, hash.String())
	}
	if err != nil {
		return nil, err
	}
	return []attestation.Envelope{env}, nil
}
