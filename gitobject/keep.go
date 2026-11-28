// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package gitobject

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

	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/repository"
	intotostatement "github.com/policylabs/collector/statement/intoto"
)

// Keys of the reassembly material recorded with a kept git object: what an
// attestation is built from that the object itself does not hold. A driver
// may record more under keys of its own.
const (
	// MaterialObject is the type of the object kept: commit or tag.
	MaterialObject = "object"
	// MaterialRemote is the name of the remote the subject is named after
	// and MaterialURL its URL, absent when the repository had no such
	// remote.
	MaterialRemote = "remote"
	MaterialURL    = "url"
)

// ObjectOrigin returns the origin of an attestation synthesized from a git
// commit or tag, for the drivers asked to keep the content of what they
// read.
//
// The content is the object as git stores it, signature included, and the
// digest is the object's own id (gitCommit or gitTag): hashing the content
// the way git does gives it back. It has no media type, as no envelope
// parser reads a git object. The origin names instead, by its moniker, the
// repository type that builds the attestation again from the object, and
// records the remote the subjects are named after with whatever else the
// driver needs in extra.
func ObjectOrigin(
	repo *gogit.Repository, objType plumbing.ObjectType, hash plumbing.Hash,
	moniker, remote string, extra map[string]any,
) (*intoto.ResourceDescriptor, error) {
	algo, err := objectAlgorithm(objType)
	if err != nil {
		return nil, err
	}
	obj, err := repo.Storer.EncodedObject(objType, hash)
	if err != nil {
		return nil, fmt.Errorf("reading %s %s: %w", objType, hash, err)
	}
	reader, err := obj.Reader()
	if err != nil {
		return nil, fmt.Errorf("opening %s %s: %w", objType, hash, err)
	}
	defer reader.Close() //nolint:errcheck
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading %s %s: %w", objType, hash, err)
	}

	origin := &intoto.ResourceDescriptor{
		Name:    hash.String(),
		Digest:  map[string]string{algo: hash.String()},
		Content: data,
	}

	material := map[string]any{}
	for k, v := range extra {
		material[k] = v
	}
	material[MaterialObject] = objType.String()
	material[MaterialRemote] = remote
	if remote != "" {
		if r, err := repo.Remote(remote); err == nil && r.Config() != nil && len(r.Config().URLs) > 0 {
			material[MaterialURL] = r.Config().URLs[0]
		}
	}
	if err := repository.Annotate(origin, moniker, material); err != nil {
		return nil, err
	}
	return origin, nil
}

// Origin returns the origin of an attestation the synthesizer built from a
// commit or tag of a repository (see ObjectOrigin), naming the repository
// type that reassembles it. When the remote the subjects are named after is
// known, the origin locates the object in it.
func (s *Synthesizer) Origin(repo *gogit.Repository, objType plumbing.ObjectType, hash plumbing.Hash, moniker string) (*intoto.ResourceDescriptor, error) {
	origin, err := ObjectOrigin(repo, objType, hash, moniker, s.remote, nil)
	if err != nil {
		return nil, err
	}
	if url := s.subjectName(repo); url != "" {
		origin.Uri = "git+" + url + "@" + hash.String()
	}
	return origin, nil
}

// objectAlgorithm returns the in-toto digest algorithm of a commit or tag id.
func objectAlgorithm(objType plumbing.ObjectType) (string, error) {
	if objType == plumbing.CommitObject {
		return intoto.AlgorithmGitCommit.String(), nil
	}
	if objType == plumbing.TagObject {
		return intoto.AlgorithmGitTag.String(), nil
	}
	return "", fmt.Errorf("not a commit or tag (%q)", objType)
}

// Restored is a git object read back from the origin that kept it, in a
// repository of its own.
type Restored struct {
	// Repo is an in-memory repository holding the object and, when the
	// origin recorded one, the remote the subjects are named after.
	Repo *gogit.Repository
	Type plumbing.ObjectType
	Hash plumbing.Hash
	// Remote is the name of that remote.
	Remote string
	// Material is all the reassembly material the origin recorded.
	Material map[string]any
}

// RestoreObject reads back the git object kept in an origin by ObjectOrigin.
// It refuses content that is not the object the origin says it is.
func RestoreObject(origin *intoto.ResourceDescriptor) (*Restored, error) {
	material := repository.Material(origin)
	if material == nil {
		return nil, errors.New("origin has no reassembly material")
	}
	str := func(k string) string {
		s, _ := material[k].(string) //nolint:errcheck // an absent or odd value reads as empty
		return s
	}

	objType, err := plumbing.ParseObjectType(str(MaterialObject))
	if err != nil {
		return nil, fmt.Errorf("reassembly material names no commit or tag (%q)", str(MaterialObject))
	}
	algo, err := objectAlgorithm(objType)
	if err != nil {
		return nil, fmt.Errorf("reassembly material names no commit or tag (%q)", str(MaterialObject))
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
	if want := origin.GetDigest()[algo]; want != hash.String() {
		return nil, fmt.Errorf("kept %s is %s, not %s as its origin says", objType, hash, want)
	}

	remote := str(MaterialRemote)
	if url := str(MaterialURL); url != "" && remote != "" {
		if _, err := repo.CreateRemote(&config.RemoteConfig{Name: remote, URLs: []string{url}}); err != nil {
			return nil, fmt.Errorf("creating remote: %w", err)
		}
	}
	return &Restored{Repo: repo, Type: objType, Hash: hash, Remote: remote, Material: material}, nil
}

// WithOrigin returns a copy of an attestation built by a Synthesizer whose
// predicate has the given origin. The attestation itself is left as it is:
// a driver that builds its attestations once and serves them to every fetch
// can hand out the copy to the fetches that ask to keep content.
func WithOrigin(env attestation.Envelope, origin *intoto.ResourceDescriptor) (attestation.Envelope, error) {
	if env == nil {
		return nil, errors.New("no attestation to give an origin to")
	}
	stmt, ok := env.GetStatement().(*intotostatement.Statement)
	if !ok {
		return nil, fmt.Errorf("attestation was not built by a synthesizer (statement is %T)", env.GetStatement())
	}
	pred, ok := stmt.GetPredicate().(*generic.Predicate)
	if !ok {
		return nil, fmt.Errorf("attestation was not built by a synthesizer (predicate is %T)", stmt.GetPredicate())
	}
	cp := *pred
	cp.Source = origin
	return NewEnvelope(intotostatement.NewStatement(
		intotostatement.WithPredicate(&cp),
		intotostatement.WithSubject(stmt.GetSubject()...),
	)), nil
}

// Reassemble rebuilds the attestation a Synthesizer made of the git object
// kept in an origin: the object is read back into a repository of its own
// and described again. The signature of the object is verified again,
// against the keys in the options and the ones the package ships with,
// which is what gives the attestation its verification.
func Reassemble(ctx context.Context, origin *intoto.ResourceDescriptor, opts repository.ReassembleOptions) ([]attestation.Envelope, error) {
	restored, err := RestoreObject(origin)
	if err != nil {
		return nil, err
	}
	s := New(WithRemote(restored.Remote), WithKeys(opts.Keys...))

	var env attestation.Envelope
	if restored.Type == plumbing.TagObject {
		env, err = s.Tag(ctx, restored.Repo, restored.Hash)
	} else {
		env, err = s.Commit(ctx, restored.Repo, restored.Hash)
	}
	if err != nil {
		return nil, err
	}
	return []attestation.Envelope{env}, nil
}
