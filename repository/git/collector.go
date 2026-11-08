// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package git implements an attestations collector that works on a git
// repository. It clones the locator's ref and reads attestations from the
// checkout through the filesystem collector, and it describes git objects as
// attestations synthesized by the gitobject library (predicate types
// https://carabiner.dev/git/commit/v0 and https://carabiner.dev/git/tag/v0):
// the object the locator lands on, the checked-out commit always and the tag
// when the ref is an annotated tag, and any other commit of the repository a
// subject query asks about, fetched on demand. A policy can thus chain from a
// tag to its commit to its tree, or to a commit no branch reaches any more,
// with every hop proven by git itself.
package git

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/helper/iofs"
	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/gitobject"
	"github.com/policylabs/collector/repository/filesystem"
)

var TypeMoniker = "git"

// Build is the factory the agent calls with the locator after "git:", for
// example https://github.com/owner/repo@v1.0.0#path.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithLocator(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

// shaPattern matches a full or abbreviated commit sha.
var shaPattern = regexp.MustCompile(`^[a-f0-9]{7,40}$`)

// remoteName is the name the clone gives the repository it reads.
const remoteName = "origin"

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options:     opts,
		synthesizer: gitobject.New(),
	}, nil
}

type Collector struct {
	Repo        *git.Repository
	FSCollector *filesystem.Collector
	Options     Options

	synthesizer *gitobject.Synthesizer
	keys        []key.PublicKeyProvider
	// objects are the attestations describing the checked-out commit and,
	// when the ref is an annotated tag, the tag; built once at clone.
	objects []attestation.Envelope
	// described caches the attestations of commits fetched on demand for a
	// subject query, by sha; a sha that could not be described is nil.
	described   map[string]attestation.Envelope
	describedMu sync.Mutex
}

// SetKeys sets the keys that verify detached signatures in the checkout and
// the PGP signatures of the described git objects.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.keys = keys
	c.synthesizer.SetKeys(keys)
	if c.FSCollector != nil {
		c.FSCollector.SetKeys(keys)
	}
}

// clone clones the repository and sets up the filesystem and fs collector
func (c *Collector) clone(ctx context.Context) error {
	// For now we clone the data to memory, this could
	// be an option
	fs := memfs.New()

	ref, err := c.resolveRef(ctx)
	if err != nil {
		return err
	}

	var r *git.Repository
	if ref == "" || ref.IsBranch() || ref.IsTag() {
		// Make a shallow clone of the repo to memory
		r, err = git.CloneContext(ctx, memory.NewStorage(), fs, &git.CloneOptions{
			URL:           c.Options.URL,
			ReferenceName: ref,
			SingleBranch:  true,
			Depth:         1,
		})
		if err != nil {
			return fmt.Errorf("cloning repo: %w", err)
		}
	} else {
		// A commit: fetch only that object and check it out.
		r, err = c.fetchCommit(ctx, fs, plumbing.Revision(ref))
		if err != nil {
			return err
		}
	}
	c.Repo = r

	fsOpts := []filesystem.OptFn{
		filesystem.WithFS(iofs.New(fs)),
		filesystem.WithPath(c.Options.Path),
	}
	if c.Options.Extensions != nil {
		fsOpts = append(fsOpts, filesystem.WithExtensions(c.Options.Extensions))
	}
	fscollector, err := filesystem.New(fsOpts...)
	if err != nil {
		return fmt.Errorf("creating new fs collector: %w", err)
	}
	if c.keys != nil {
		fscollector.SetKeys(c.keys)
	}
	c.FSCollector = fscollector

	objects, err := c.describe(ctx, ref)
	if err != nil {
		return err
	}
	c.objects = objects
	return nil
}

// resolveRef turns the locator's ref into something clonable: "" (the
// remote's HEAD), a full reference name, or a commit sha (returned as a
// plain reference name that is neither branch nor tag). A short name is
// looked up on the remote, tags first, then branches, so "v1.2.0" and
// "main" both work without their refs/ prefix.
func (c *Collector) resolveRef(ctx context.Context) (plumbing.ReferenceName, error) {
	ref := c.Options.Ref
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "refs/"):
		return plumbing.ReferenceName(ref), nil
	case shaPattern.MatchString(ref):
		return plumbing.ReferenceName(ref), nil
	}
	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: remoteName,
		URLs: []string{c.Options.URL},
	})
	refs, err := remote.ListContext(ctx, &git.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("listing remote refs to resolve %q: %w", ref, err)
	}
	for _, candidate := range []plumbing.ReferenceName{
		plumbing.NewTagReferenceName(ref), plumbing.NewBranchReferenceName(ref),
	} {
		for _, r := range refs {
			if r.Name() == candidate {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("ref %q is neither a tag nor a branch on %s", ref, c.Options.URL)
}

// fetchCommit fetches a single commit into a fresh repository and, when fs
// is not nil, checks it out there. A full sha is fetched alone where the
// remote allows fetching by object id (GitHub does); elsewhere, and for an
// abbreviated sha, the default branch is cloned in full and the commit
// resolved in it.
func (c *Collector) fetchCommit(ctx context.Context, fs billy.Filesystem, sha plumbing.Revision) (*git.Repository, error) {
	if len(sha) == 40 {
		r, err := git.Init(memory.NewStorage(), fs)
		if err != nil {
			return nil, fmt.Errorf("initializing repository: %w", err)
		}
		if _, err := r.CreateRemote(&config.RemoteConfig{Name: remoteName, URLs: []string{c.Options.URL}}); err != nil {
			return nil, fmt.Errorf("creating remote: %w", err)
		}
		local := plumbing.NewBranchReferenceName("collector")
		err = r.FetchContext(ctx, &git.FetchOptions{
			RemoteName: remoteName,
			Depth:      1,
			Tags:       git.NoTags,
			RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf("+%s:%s", sha, local))},
		})
		switch {
		case err == nil || errors.Is(err, git.NoErrAlreadyUpToDate):
			if fs == nil {
				return r, nil
			}
			return r, checkout(r, &git.CheckoutOptions{Branch: local})
		case strings.Contains(err.Error(), "exact SHA1"):
			logrus.Debugf("git: %s does not serve commits by sha, cloning history", c.Options.URL)
		default:
			return nil, fmt.Errorf("fetching commit %s: %w", sha, err)
		}
	}
	r, err := git.CloneContext(ctx, memory.NewStorage(), fs, &git.CloneOptions{URL: c.Options.URL, Tags: git.NoTags, NoCheckout: fs == nil})
	if err != nil {
		return nil, fmt.Errorf("cloning repo: %w", err)
	}
	hash, err := r.ResolveRevision(sha)
	if err != nil {
		return nil, fmt.Errorf("resolving commit %s: %w", sha, err)
	}
	if fs == nil {
		return r, nil
	}
	return r, checkout(r, &git.CheckoutOptions{Hash: *hash})
}

// describeCommit returns the attestation of a commit a subject query asks
// about: the checked-out one when it is that, otherwise the commit is
// fetched alone, described and remembered. A sha that is not a commit of
// the repository, or cannot be reached, yields nil.
func (c *Collector) describeCommit(ctx context.Context, sha string) attestation.Envelope {
	c.describedMu.Lock()
	defer c.describedMu.Unlock()
	if env, ok := c.described[sha]; ok {
		return env
	}
	if c.described == nil {
		c.described = map[string]attestation.Envelope{}
	}
	var env attestation.Envelope
	if r, err := c.fetchCommit(ctx, nil, plumbing.Revision(sha)); err != nil {
		logrus.Debugf("git: not describing %s: %v", sha, err)
	} else if hash, err := r.ResolveRevision(plumbing.Revision(sha)); err != nil {
		logrus.Debugf("git: not describing %s: %v", sha, err)
	} else if env, err = c.synthesizer.Commit(ctx, r, *hash); err != nil {
		logrus.Debugf("git: not describing %s: %v", sha, err)
		env = nil
	}
	c.described[sha] = env
	return env
}

func checkout(r *git.Repository, opts *git.CheckoutOptions) error {
	wt, err := r.Worktree()
	if err != nil {
		return fmt.Errorf("opening worktree: %w", err)
	}
	if err := wt.Checkout(opts); err != nil {
		return fmt.Errorf("checking out: %w", err)
	}
	return nil
}

// describe synthesizes the attestations of the objects the locator lands
// on: the checked-out commit and, when ref is an annotated tag, the tag.
func (c *Collector) describe(ctx context.Context, ref plumbing.ReferenceName) ([]attestation.Envelope, error) {
	head, err := c.Repo.Head()
	if err != nil {
		return nil, fmt.Errorf("reading HEAD: %w", err)
	}
	commit, err := c.synthesizer.Commit(ctx, c.Repo, head.Hash())
	if err != nil {
		return nil, fmt.Errorf("describing commit %s: %w", head.Hash(), err)
	}
	objects := []attestation.Envelope{commit}
	if !ref.IsTag() {
		return objects, nil
	}
	tag, err := c.synthesizer.TagNamed(ctx, c.Repo, ref.String())
	switch {
	case errors.Is(err, gitobject.ErrLightweightTag):
		logrus.Debugf("git: %s is a lightweight tag, no tag object to describe", ref.Short())
	case err != nil:
		return nil, fmt.Errorf("describing tag %s: %w", ref.Short(), err)
	default:
		objects = append(objects, tag)
	}
	return objects, nil
}

func (c *Collector) ensureClone(ctx context.Context) error {
	if c.FSCollector == nil {
		return c.clone(ctx)
	}
	return nil
}

// Fetch returns the attestations describing the checked-out objects and the
// ones read from the checkout.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if err := c.ensureClone(ctx); err != nil {
		return nil, err
	}
	files, err := c.FSCollector.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}
	return limit(append(append([]attestation.Envelope{}, c.objects...), files...), opts), nil
}

// FetchBySubject returns the attestations whose subjects carry any of the
// digests: the described objects, the checkout's files, and, for a commit
// sha the checkout does not describe, that commit fetched on demand. This
// is how a chain that lands on a commit no branch reaches any more, a pull
// request's head after a squash, still finds the commit described.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	if err := c.ensureClone(ctx); err != nil {
		return nil, err
	}
	files, err := c.FSCollector.FetchBySubject(ctx, opts, subj)
	if err != nil {
		return nil, err
	}
	matcher := &filters.SubjectHashMatcher{HashSets: make([]map[string]string, 0, len(subj))}
	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}
	objects := attestation.NewQuery().WithFilter(matcher).Run(c.objects)
	if len(objects) == 0 {
		for sha := range commitShas(subj) {
			if env := c.describeCommit(ctx, sha); env != nil {
				objects = append(objects, env)
			}
		}
		objects = attestation.NewQuery().WithFilter(matcher).Run(objects)
	}
	return limit(append(objects, files...), opts), nil
}

// commitShas returns the full commit shas the subjects name.
func commitShas(subj []attestation.Subject) map[string]struct{} {
	shas := map[string]struct{}{}
	for _, s := range subj {
		for _, algo := range []string{"sha1", "gitCommit"} {
			if v := s.GetDigest()[algo]; len(v) == 40 {
				shas[v] = struct{}{}
			}
		}
	}
	return shas
}

// FetchByPredicateType returns the attestations of the given types, from the
// described objects and from the checkout.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	if err := c.ensureClone(ctx); err != nil {
		return nil, err
	}
	files, err := c.FSCollector.FetchByPredicateType(ctx, opts, pts)
	if err != nil {
		return nil, err
	}
	matcher := &filters.PredicateTypeMatcher{PredicateTypes: make(map[attestation.PredicateType]struct{}, len(pts))}
	for _, pt := range pts {
		matcher.PredicateTypes[pt] = struct{}{}
	}
	objects := attestation.NewQuery().WithFilter(matcher).Run(c.objects)
	return limit(append(objects, files...), opts), nil
}

func limit(envs []attestation.Envelope, opts attestation.FetchOptions) []attestation.Envelope {
	if opts.Limit > 0 && len(envs) > opts.Limit {
		return envs[:opts.Limit]
	}
	return envs
}
