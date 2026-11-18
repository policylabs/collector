// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"context"
	"fmt"
	"slices"

	"github.com/carabiner-dev/ghrfs"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"

	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/repository/filesystem"
)

var _ attestation.Fetcher = (*Collector)(nil)

var TypeMoniker = "release"

// parallelDownloads is how many release assets are downloaded at a time.
// Attestations and their sidecars are small files, so the time goes to
// round trips and not to bandwidth: ghrfs's default of three makes a
// release with a hundred of them wait on the queue.
const parallelDownloads = 8

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReleaseURL(istr))
}

func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{
		Options:        defaultOptions,
		apiBaseURL:     defaultAPIBaseURL,
		uploadsBaseURL: defaultUploadsBaseURL,
	}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}

	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	fs, err := ghrfs.New(
		ghrfs.FromURL(
			fmt.Sprintf("%s/releases/tag/%s", c.Options.RepoURL, c.Options.Tag),
		),
		ghrfs.WithToken(c.Options.Token),
		ghrfs.WithRetries(c.Options.Retries),
		ghrfs.WithCache(true),
		ghrfs.WithParallelDownloads(parallelDownloads),
		ghrfs.WithCacheExtensions(cacheExtensions(c.Options.Extensions)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating GHRFS from: %w", err)
	}

	fscollector, err := filesystem.New(
		filesystem.WithFS(fs),
		filesystem.WithKey(c.Keys...),
		filesystem.WithExtensions(attestationExtensions(c.Options.Extensions)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem collector driver: %w", err)
	}
	c.Driver = fscollector

	return c, nil
}

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
	Driver  attestation.Fetcher

	// GitHub REST hosts used when uploading attestations (Store). They default
	// to the public GitHub endpoints and are overridable in tests.
	apiBaseURL     string
	uploadsBaseURL string
}

// SetKeys sets the verification keys on the release collector and propagates
// them to the inner driver if it supports key acceptance.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
	type keyAcceptor interface {
		SetKeys([]key.PublicKeyProvider)
	}
	if ka, ok := c.Driver.(keyAcceptor); ok {
		ka.SetKeys(keys)
	}
}

// Fetch queries the repository and retrieves any attestations matching the query.
// Attestations are read from the release assets and, for immutable releases,
// from the attestation GitHub generates for the release itself.
//
// The two sources do not depend on each other, so the release attestations
// are looked up in GitHub's API while the assets are read. The assets come
// first in the result and count first towards the fetch limit: when they
// meet it on their own the lookup is abandoned.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	lookupCtx, abandon := context.WithCancel(ctx)
	defer abandon()
	lookup := make(chan releaseLookup, 1)
	go func() {
		var res releaseLookup
		defer func() {
			// The lookup parses remote data away from the caller's
			// goroutine, where a panic would take the process down.
			if r := recover(); r != nil {
				res = releaseLookup{err: fmt.Errorf("panic: %v", r)}
			}
			lookup <- res
		}()
		res.atts, res.err = c.fetchReleaseAttestations(lookupCtx, opts)
	}()

	atts, err := c.Driver.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 && len(atts) >= opts.Limit {
		return atts[:opts.Limit], nil
	}

	res := <-lookup
	if res.err != nil {
		return nil, fmt.Errorf("reading release attestations: %w", res.err)
	}
	relAtts := res.atts
	if opts.Query != nil {
		relAtts = opts.Query.Run(relAtts)
	}
	atts = append(atts, relAtts...)
	if opts.Limit > 0 && len(atts) > opts.Limit {
		atts = atts[:opts.Limit]
	}
	return atts, nil
}

// releaseLookup is the outcome of looking up a release's own attestations.
type releaseLookup struct {
	atts []attestation.Envelope
	err  error
}

// FetchBySubject retrieves the release attestations matching the subjects.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	sets := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		sets = append(sets, s.GetDigest())
	}
	return c.Fetch(ctx, withFilter(opts, &filters.SubjectHashMatcher{HashSets: sets}))
}

// FetchByPredicateType retrieves the release attestations of the given types.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	m := make(map[attestation.PredicateType]struct{}, len(pts))
	for _, pt := range pts {
		m[pt] = struct{}{}
	}
	return c.Fetch(ctx, withFilter(opts, &filters.PredicateTypeMatcher{PredicateTypes: m}))
}

// withFilter returns a copy of opts with the filter appended to its query, so
// that both the release assets and the release attestations are filtered
// before the fetch limit is applied.
func withFilter(opts attestation.FetchOptions, f attestation.Filter) attestation.FetchOptions {
	if opts.Query == nil {
		opts.Query = &attestation.Query{Filters: []attestation.Filter{f}}
		return opts
	}
	q := *opts.Query
	q.Filters = append(append([]attestation.Filter{}, q.Filters...), f)
	opts.Query = &q
	return opts
}

// sidecarExtensions are the extensions of the files published next to
// attestations that the filesystem collector pairs with them: detached
// signatures, certificates and keys.
var sidecarExtensions = []string{"sig", "asc", "gpg", "pem", "crt", "cert", "key", "pub"}

// attestationExtensions returns the extensions attestations are read from:
// the configured ones or the filesystem collector's defaults.
func attestationExtensions(configured []string) []string {
	if configured != nil {
		return slices.Clone(configured)
	}
	return slices.Clone(filesystem.DefaultExtensions)
}

// cacheExtensions returns the extensions of the release assets worth
// downloading: the attestation extensions plus their sidecars.
func cacheExtensions(configured []string) []string {
	exts := attestationExtensions(configured)
	for _, ext := range sidecarExtensions {
		if !slices.Contains(exts, ext) {
			exts = append(exts, ext)
		}
	}
	return exts
}
