// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package gitsign implements a collector that synthesizes virtual attestations
// from git commit signatures. It uses the gitsign library to extract an in-toto
// statement with predicate type https://gitsign.sigstore.dev/predicate/git/v0.1
// and then verifies the commit signature to populate the verification identity.
package gitsign

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	"github.com/sigstore/gitsign/pkg/attest"
	gspredicate "github.com/sigstore/gitsign/pkg/predicate"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/gitobject"
	"github.com/policylabs/collector/predicate/generic"
	intotostatement "github.com/policylabs/collector/statement/intoto"
)

var TypeMoniker = "gitsign"

// Build is the factory function registered with the collector agent.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInitString(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider

	// verifier checks the objects' signatures: sigstore (CMS, Fulcio chain,
	// Rekor entry) and PGP against Keys. The code lives in the gitobject
	// library, shared with the git driver.
	verifier *gitobject.Verifier
}

// defaultRekorURL is the sigstore public-good transparency log, queried for the
// online-mode Rekor lookup when a signature carries no embedded entry.
const defaultRekorURL = gitobject.DefaultRekorURL

type Options struct {
	// Locator is the raw init string. It is parsed as a vcslocator for
	// remote repositories or treated as a local path.
	Locator string

	// Remote is the git remote name used to populate the subject name.
	Remote string

	// RekorURL is the transparency log queried when verifying online-mode
	// signatures (those without an embedded Rekor entry). Defaults to the
	// sigstore public-good instance.
	RekorURL string

	// Auth authenticates the remote fetch. When nil, openRepo falls back to
	// vcslocator.GetAuthMethod (system git credentials). Set it (e.g. via
	// WithToken) to read private repositories or pull-request refs.
	Auth transport.AuthMethod

	// Ref is an explicit git ref to fetch (e.g. "refs/pull/42/head"). When set,
	// openRepo fetches only that ref instead of cloning every branch, which is
	// how a PR head — including a fork PR under refs/pull/N/head — is reached.
	// When empty, the ref parsed from the locator (if any) is used.
	Ref string

	// Depth limits the fetched history. 0 fetches full history; 1 fetches only
	// the ref tip, which is sufficient when the subject commit is that tip.
	Depth int
}

var defaultOptions = Options{
	Remote:   "origin",
	RekorURL: defaultRekorURL,
	// Depth 1 is a lean, single-commit fetch. gitsign verification only needs
	// the target commit/tag object and its signature, never history, so the
	// collector always shallow-fetches by default (WithDepth overrides it).
	Depth: 1,
}

type optFn func(*Collector) error

func WithInitString(s string) optFn {
	return func(c *Collector) error {
		c.Options.Locator = strings.TrimPrefix(s, TypeMoniker+":")
		return nil
	}
}

func WithRepoPath(path string) optFn {
	return func(c *Collector) error {
		c.Options.Locator = path
		return nil
	}
}

func WithRemote(remote string) optFn {
	return func(c *Collector) error {
		c.Options.Remote = remote
		return nil
	}
}

// WithRekorURL sets the transparency log used for the online-mode Rekor lookup.
func WithRekorURL(url string) optFn {
	return func(c *Collector) error {
		c.Options.RekorURL = url
		return nil
	}
}

// WithAuth sets an explicit transport auth method for the remote fetch.
func WithAuth(auth transport.AuthMethod) optFn {
	return func(c *Collector) error {
		c.Options.Auth = auth
		return nil
	}
}

// WithToken authenticates the remote fetch with a bearer/installation token,
// using GitHub's "x-access-token" basic-auth convention. This is what lets the
// collector read private repositories and pull-request refs.
func WithToken(token string) optFn {
	return func(c *Collector) error {
		c.Options.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
		return nil
	}
}

// WithRef sets an explicit git ref to fetch (e.g. "refs/pull/42/head"), so the
// collector reads exactly that ref instead of cloning every branch.
func WithRef(ref string) optFn {
	return func(c *Collector) error {
		c.Options.Ref = ref
		return nil
	}
}

// WithDepth limits the fetched history (1 = a shallow single-commit fetch).
func WithDepth(depth int) optFn {
	return func(c *Collector) error {
		c.Options.Depth = depth
		return nil
	}
}

func WithKeys(keys ...key.PublicKeyProvider) optFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

func New(opts ...optFn) (*Collector, error) {
	c := &Collector{
		Options: defaultOptions,
	}
	for _, fn := range opts {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if c.Options.Locator == "" {
		return nil, errors.New("repository path is required")
	}
	c.verifier = gitobject.NewVerifier(gitobject.WithRekorURL(c.Options.RekorURL))
	c.verifier.SetKeys(c.Keys)
	return c, nil
}

// SetKeys implements the repository.SignatureVerifier interface.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
	c.verifier.SetKeys(keys)
}

// Fetch parses the locator and, if it contains a commit or tag reference, builds a
// virtual attestation. Tag locators produce a tag predicate; commit locators
// produce a commit predicate.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err != nil {
		return []attestation.Envelope{}, nil //nolint:nilerr // unparseable locator means no commit to fetch
	}

	if components.Commit == "" && components.Tag == "" {
		return []attestation.Envelope{}, nil
	}

	repo, err := c.openRepo(ctx)
	if err != nil {
		return nil, err
	}

	var env attestation.Envelope
	if components.Tag != "" {
		env, err = c.buildVirtualTagAttestation(ctx, repo, components.Tag)
		if err != nil {
			logrus.Debugf("gitsign: skipping tag %s: %v", components.Tag, err)
			return []attestation.Envelope{}, nil
		}
	} else {
		env, err = c.buildVirtualAttestation(ctx, repo, components.Commit)
		if err != nil {
			return nil, fmt.Errorf("building attestation for commit %s: %w", components.Commit, err)
		}
	}

	ret := []attestation.Envelope{env}

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// FetchByPredicateType returns attestations only if the requested predicate
// types include a gitsign type. This avoids unnecessary work when the caller
// is looking for unrelated predicate types.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, types []attestation.PredicateType) ([]attestation.Envelope, error) {
	match := false
	for _, t := range types {
		if t == attestation.PredicateType(gspredicate.TypeV01) || t == attestation.PredicateType(gspredicate.TagTypeV01) {
			match = true
			break
		}
	}
	if !match {
		return nil, nil
	}

	envs, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Filter to only the requested predicate types.
	typeSet := make(map[attestation.PredicateType]struct{}, len(types))
	for _, t := range types {
		typeSet[t] = struct{}{}
	}

	ret := make([]attestation.Envelope, 0, len(envs))
	for _, env := range envs {
		if p := env.GetPredicate(); p != nil {
			if _, ok := typeSet[p.GetType()]; ok {
				ret = append(ret, env)
			}
		}
	}

	return ret, nil
}

// FetchBySubject looks for sha1 or gitCommit digest algorithms in the
// requested subjects, generates a gitsign virtual attestation for each
// matching commit, and returns them.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	commits := map[string]struct{}{}
	for _, s := range subj {
		for algo, val := range s.GetDigest() {
			if algo == intoto.AlgorithmSHA1.String() || algo == intoto.AlgorithmGitCommit.String() {
				commits[val] = struct{}{}
			}
		}
	}

	if len(commits) == 0 {
		return nil, nil
	}

	repo, err := c.openRepo(ctx)
	if err != nil {
		return nil, err
	}

	var ret []attestation.Envelope
	for hash := range commits {
		env, err := c.buildVirtualAttestation(ctx, repo, hash)
		if err != nil {
			logrus.Debugf("gitsign: skipping commit %s: %v", hash, err)
			continue
		}
		ret = append(ret, env)
	}

	matcher := &filters.SubjectHashMatcher{
		HashSets: make([]map[string]string, 0, len(subj)),
	}
	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}
	ret = attestation.NewQuery().WithFilter(matcher).Run(ret)

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// openRepo opens a local repository or clones a remote one into memory.
// The locator is first tried as a vcslocator; if it parses and is not a
// file:// transport, the repository is cloned. Otherwise it is treated as
// a local filesystem path.
func (c *Collector) openRepo(ctx context.Context) (*gogit.Repository, error) {
	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err == nil && components.Transport != vcslocator.TransportFile {
		// Remote repository — fetch into memory. An explicit auth option wins,
		// otherwise fall back to system git credentials.
		auth := c.Options.Auth
		if auth == nil {
			auth, err = vcslocator.GetAuthMethod(c.Options.Locator)
			if err != nil {
				return nil, fmt.Errorf("getting auth method: %w", err)
			}
		}

		// An explicit ref option wins, otherwise use the ref parsed from the
		// locator (e.g. an "@refs/pull/42/head" suffix).
		ref := c.Options.Ref
		if ref == "" {
			ref = components.RefString
		}

		// With a specific ref, fetch only that ref — this reaches PR heads
		// (including fork PRs under refs/pull/N/head) that a default-branch
		// clone never sees. Otherwise fall back to a full clone.
		if ref != "" {
			return fetchRef(ctx, components.RepoURL(), c.Options.Remote, ref, auth, c.Options.Depth)
		}

		repo, err := gogit.CloneContext(ctx, memory.NewStorage(), nil, &gogit.CloneOptions{
			URL:   components.RepoURL(),
			Auth:  auth,
			Depth: c.Options.Depth,
		})
		if err != nil {
			return nil, fmt.Errorf("cloning repository: %w", err)
		}
		return repo, nil
	}

	// Local path (either file:// vcslocator or plain path).
	path := c.Options.Locator
	if err == nil && components.Transport == vcslocator.TransportFile {
		path, err = vcslocator.Locator(c.Options.Locator).LocalPath()
		if err != nil {
			return nil, fmt.Errorf("resolving local path: %w", err)
		}
	}

	repo, err := gogit.PlainOpenWithOptions(path, &gogit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return nil, fmt.Errorf("opening local repository: %w", err)
	}
	return repo, nil
}

// fetchRef fetches a single ref from a remote into an in-memory repository,
// without cloning any other branch. This reaches refs a default clone does not
// — notably refs/pull/N/head, where GitHub exposes a pull request's head commit
// (fork PRs included) on the base repository, readable with the base repo's
// installation token. depth 0 fetches full history; 1 fetches only the ref tip.
func fetchRef(ctx context.Context, url, remote, ref string, auth transport.AuthMethod, depth int) (*gogit.Repository, error) {
	if remote == "" {
		remote = "origin"
	}
	repo, err := gogit.Init(memory.NewStorage(), nil)
	if err != nil {
		return nil, fmt.Errorf("initializing repository: %w", err)
	}
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: remote,
		URLs: []string{url},
	}); err != nil {
		return nil, fmt.Errorf("creating remote: %w", err)
	}
	if err := repo.FetchContext(ctx, &gogit.FetchOptions{
		RemoteName: remote,
		Auth:       auth,
		Depth:      depth,
		Tags:       gogit.NoTags,
		RefSpecs:   []config.RefSpec{config.RefSpec(fmt.Sprintf("+%s:%s", ref, ref))},
	}); err != nil && !errors.Is(err, gogit.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("fetching ref %q: %w", ref, err)
	}
	return repo, nil
}

// buildVirtualAttestation generates the gitsign predicate for a commit and
// wraps it in a virtual envelope with verification data.
func (c *Collector) buildVirtualAttestation(ctx context.Context, repo *gogit.Repository, commitHash string) (attestation.Envelope, error) {
	stmt, err := attest.CommitStatement(repo, c.Options.Remote, commitHash)
	if err != nil {
		return nil, fmt.Errorf("generating commit statement: %w", err)
	}

	predData, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	hash := plumbing.NewHash(commitHash)
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit object: %w", err)
	}

	verification := c.verifier.Verify(ctx, commit, commit.PGPSignature)

	pred := &generic.Predicate{
		Type: attestation.PredicateType(gspredicate.TypeV01),
		Data: predData,
	}

	if verification != nil {
		pred.SetVerification(verification)
	}

	// Enrich subjects: ensure both sha1 and gitCommit digests are present
	// so the attestation matches queries using either algorithm.
	subjects := make([]*intoto.ResourceDescriptor, 0, len(stmt.GetSubject()))
	for _, s := range stmt.GetSubject() {
		digests := s.GetDigest()
		if v, ok := digests[intoto.AlgorithmSHA1.String()]; ok {
			if _, has := digests[intoto.AlgorithmGitCommit.String()]; !has {
				digests[intoto.AlgorithmGitCommit.String()] = v
			}
		}
		if v, ok := digests[intoto.AlgorithmGitCommit.String()]; ok {
			if _, has := digests[intoto.AlgorithmSHA1.String()]; !has {
				digests[intoto.AlgorithmSHA1.String()] = v
			}
		}
		subjects = append(subjects, s)
	}

	stmtObj := intotostatement.NewStatement(
		intotostatement.WithPredicate(pred),
		intotostatement.WithSubject(subjects...),
	)

	return &virtualEnvelope{statement: stmtObj}, nil
}

// buildVirtualTagAttestation generates a tag predicate for an annotated tag
// and wraps it in a virtual envelope with verification data.
func (c *Collector) buildVirtualTagAttestation(ctx context.Context, repo *gogit.Repository, tagName string) (attestation.Envelope, error) {
	stmt, err := attest.TagStatement(repo, c.Options.Remote, tagName)
	if err != nil {
		return nil, fmt.Errorf("generating tag statement: %w", err)
	}

	predData, err := protojson.Marshal(stmt.GetPredicate())
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	pred := &generic.Predicate{
		Type: attestation.PredicateType(gspredicate.TagTypeV01),
		Data: predData,
	}

	// Extract verification from the tag's signature.
	ref, err := repo.Tag(tagName)
	if err != nil {
		return nil, err
	}
	tagObj, err := repo.TagObject(ref.Hash())
	if err == nil && tagObj.PGPSignature != "" {
		if verification := c.verifier.Verify(ctx, tagObj, tagObj.PGPSignature); verification != nil {
			pred.SetVerification(verification)
		}
	}

	stmtObj := intotostatement.NewStatement(
		intotostatement.WithPredicate(pred),
		intotostatement.WithSubject(stmt.GetSubject()...),
	)

	return &virtualEnvelope{statement: stmtObj}, nil
}
