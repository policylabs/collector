// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package note implements an attestation fetcher that can read from
// git commit notes.
package note

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/carabiner-dev/jsonl"
	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/internal/readlimit"
)

var TypeMoniker = "note"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithLocator(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

type Collector struct {
	Options Options
}

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		fn(&opts)
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

type Options struct {
	Locator string
	// Push determines whether to push notes to remote after storing.
	// If nil, defaults to true for remote repos, false for local file:// repos.
	Push *bool

	// Username and password to use when git connects via HTTP
	HttpUsername, HttpPassword string

	// DynamicRepoURL holds the repostory URL for the dynamic notes collector
	DynamicRepoURL string
}

var defaultOptions Options

type optFn = func(*Options)

func WithInit(init string) optFn {
	return WithLocator(strings.TrimPrefix(init, TypeMoniker+":"))
}

func DynamicRepoURL(url string) optFn {
	return func(opts *Options) {
		opts.DynamicRepoURL = url
	}
}

func WithLocator(locator string) optFn {
	return func(opts *Options) {
		opts.Locator = locator
	}
}

func WithPush(push bool) optFn {
	return func(opts *Options) {
		opts.Push = &push
	}
}

func WithHttpAuth(username, password string) optFn {
	return func(opts *Options) {
		opts.HttpUsername = username
		opts.HttpPassword = password
	}
}

func (o *Options) Validate() error {
	return nil
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	ret := []attestation.Envelope{}

	reader, err := c.extractCommitBundle(ctx)
	if err != nil {
		return nil, err
	}

	for i, r := range jsonl.IterateBundle(readlimit.Reader(reader, opts.MaxReadSize)) {
		if r == nil {
			continue
		}

		// Parse the JSON doc
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("reading attestation %d: %w", i, err)
		}
		envelopes, err := envelope.Parsers.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %d in %q: %w", i, c.Options.Locator, err)
		}

		// If the json did not return anything (not likely)
		if len(envelopes) == 0 {
			continue
		}

		// Complete the attestation source, we know that the envelope returns max 1
		// attestation per line
		if envelopes[0].GetStatement() != nil &&
			envelopes[0].GetStatement().GetPredicate() != nil &&
			envelopes[0].GetStatement().GetPredicate().GetOrigin() != nil {
			rd := &intoto.ResourceDescriptor{
				Name:   fmt.Sprintf("jsonl:%s#%d", c.Options.Locator, i),
				Uri:    fmt.Sprintf("jsonl:%s#%d", c.Options.Locator, i),
				Digest: envelopes[0].GetStatement().GetPredicate().GetOrigin().GetDigest(),
			}
			envelopes[0].GetStatement().GetPredicate().SetOrigin(rd)
			if opts.KeepContent {
				envelope.KeepContent(envelopes, data)
			}
		}

		ret = append(ret, envelopes...)

		if opts.Limit > 0 && len(ret) >= opts.Limit {
			return ret[:opts.Limit], nil
		}
	}

	return ret, nil
}

// extractCommitBundle reads the jsonl attestations bundle from the commit
// notes data. Returns an error if cloning fails but nil if there is no
// bundle data in the commit.
func (c *Collector) extractCommitBundle(ctx context.Context) (io.Reader, error) {
	if c.Options.Locator == "" {
		return nil, errors.New("unable to read note, no VCS locator set")
	}

	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err != nil {
		return nil, fmt.Errorf("parsing VCS locator: %w", err)
	}

	if components.Commit == "" {
		return nil, fmt.Errorf("VCS locator must specify a commit sha")
	}

	path := components.Commit[0:2] + "/" + components.Commit[2:]

	// We need two locators because we will check for sharded notes data
	// but also for direct files at the root of the notes reference. For
	// more details check this issue:
	//   https://github.com/slsa-framework/slsa-source-poc/issues/215
	uriShard := "git+" + components.RepoURL() + "@refs/notes/commits#" + path
	uriFile := "git+" + components.RepoURL() + "@refs/notes/commits#" + components.Commit

	// vcslocator 0.3.0 does not return a url for file urls, so we need to
	// build it manually:
	if components.Transport == vcslocator.TransportFile {
		uriShard = "file://" + components.RepoPath + "@refs/notes/commits#" + path
		uriFile = "file://" + components.RepoPath + "@refs/notes/commits#" + components.Commit
	}

	var bufferShard bytes.Buffer
	var bufferFile bytes.Buffer

	// OK, now copy the note data using the standard vcslocator functions.
	// We copy them as a group as the vcs locator module optimizes the cloning
	// ops. Note that this will always err, so we don't check the error immediately.
	err = vcslocator.CopyFileGroup(
		[]string{uriShard, uriFile}, []io.Writer{&bufferShard, &bufferFile},
		vcslocator.WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
		vcslocator.WithContext(ctx),
	)

	// Depending on wether the notes data was sharded or not, one of the VCS
	// locators will contain the data and the other will err when opening the
	// non-existent file.
	switch {
	case bufferShard.Len() > 0:
		return &bufferShard, nil
	case bufferFile.Len() > 0:
		return &bufferFile, nil
	case err == nil || noteMissing(err):
		// No note data for the commit is not an error
		return &bytes.Buffer{}, nil
	default:
		return nil, err
	}
}

// noteMissing returns true when the error returned reading the note locators
// means the commit has no note rather than that reading failed: either the
// repository has no notes reference yet or none of the locators point to an
// existing file.
func noteMissing(err error) bool {
	var list *vcslocator.ErrorList
	if !errors.As(err, &list) {
		return errors.Is(err, vcslocator.ErrRefNotFound)
	}

	found := false
	for _, e := range list.Errors {
		if e == nil {
			continue
		}
		if !errors.Is(e, vcslocator.ErrRefNotFound) && !errors.Is(e, fs.ErrNotExist) {
			return false
		}
		found = true
	}
	return found
}

// FetchBySubject calls the attestation reader with a filter preconfigured
// with subject hashes.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	matcher := &filters.SubjectHashMatcher{
		HashSets: []map[string]string{},
	}

	for _, s := range subj {
		matcher.HashSets = append(matcher.HashSets, s.GetDigest())
	}

	return attestation.NewQuery().WithFilter(matcher).Run(all), nil
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	matcher := &filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{},
	}

	for _, pt := range pts {
		matcher.PredicateTypes[pt] = struct{}{}
	}

	return attestation.NewQuery().WithFilter(matcher).Run(all), nil
}
