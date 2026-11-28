// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package stash implements a collector that reads attestations from a
// Carabiner stash service.
package stash

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	stashclient "github.com/carabiner-dev/stash/pkg/client"
	stashconfig "github.com/carabiner-dev/stash/pkg/client/config"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/envelope"
)

// TypeMoniker is the string identifying the stash repository type.
const TypeMoniker = "stash"

// Ensure the collector implements the fetcher interfaces.
var (
	_ attestation.Fetcher                          = (*Collector)(nil)
	_ attestation.FetcherBySubject                 = (*Collector)(nil)
	_ attestation.FetcherByPredicateType           = (*Collector)(nil)
	_ attestation.FetcherByPredicateTypeAndSubject = (*Collector)(nil)
)

// Build implements the collector factory function. The init string addresses
// the stash tenancy to read from ("stash:<org>[/<namespace>]"); the server
// address and bearer credential come from the stash client environment
// (STASH_URL and STASH_TOKEN / the credentials manager). Programmatic callers
// use New with options instead — the credential is deliberately an option,
// never part of the init string, so configuration files cannot echo it.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInit(istr))
}

// Options configures the stash collector.
type Options struct {
	// Org and Namespace address the stash tenancy the collector reads from.
	// Org is required; an empty Namespace reads the default namespace.
	Org       string
	Namespace string

	// URL is the stash service address. When neither URL nor Token is set,
	// both come from the stash client environment.
	URL string

	// Token is the bearer presented to stash.
	Token string

	// Client overrides the constructed stash client (used by tests and by
	// callers that manage their own connection).
	Client stashclient.StashClient
}

type optFn = func(*Options)

// WithInit configures the collector from an init string
// ("stash:<org>[/<namespace>]", moniker optional).
func WithInit(init string) optFn {
	return func(opts *Options) {
		init = strings.TrimPrefix(init, TypeMoniker+":")
		org, namespace, ok := strings.Cut(init, "/")
		opts.Org = org
		if ok {
			opts.Namespace = namespace
		}
	}
}

// WithOrg sets the stash organization to read from.
func WithOrg(org string) optFn {
	return func(opts *Options) { opts.Org = org }
}

// WithNamespace sets the stash namespace to read from ("" = default).
func WithNamespace(namespace string) optFn {
	return func(opts *Options) { opts.Namespace = namespace }
}

// WithURL sets the stash service address.
func WithURL(url string) optFn {
	return func(opts *Options) { opts.URL = url }
}

// WithToken sets the bearer token presented to stash.
func WithToken(token string) optFn {
	return func(opts *Options) { opts.Token = token }
}

// WithClient sets a pre-built stash client, overriding URL/Token.
func WithClient(client stashclient.StashClient) optFn {
	return func(opts *Options) { opts.Client = client }
}

// Collector reads attestations from a stash organization/namespace.
type Collector struct {
	Options Options
	client  stashclient.StashClient
	parsers envelope.ParserList
}

// New returns a new stash collector.
func New(funcs ...optFn) (*Collector, error) {
	opts := Options{}
	for _, fn := range funcs {
		fn(&opts)
	}
	if opts.Org == "" {
		return nil, fmt.Errorf("stash collector: organization is required (init string %q)", TypeMoniker+":<org>[/<namespace>]")
	}

	client := opts.Client
	if client == nil {
		var err error
		client, err = buildClient(&opts)
		if err != nil {
			return nil, fmt.Errorf("building stash client: %w", err)
		}
	}
	return &Collector{
		Options: opts,
		client:  client,
		parsers: envelope.Parsers,
	}, nil
}

// buildClient connects to stash over gRPC (the transport whose filters are
// fully supported server-side). Explicit URL/Token options win; otherwise the
// client environment supplies both.
func buildClient(opts *Options) (stashclient.StashClient, error) {
	if opts.URL == "" && opts.Token == "" {
		return stashclient.NewGRPCClientFromEnv()
	}
	return stashclient.NewGRPCClientFromConfig(&stashconfig.Config{
		BaseURL: opts.URL,
		Token:   opts.Token,
	})
}

// Fetch retrieves attestations from the configured organization/namespace.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return c.query(ctx, opts, []*stashclient.Filters{{}})
}

// FetchBySubject retrieves the attestations matching any of the subjects.
// Stash compares digest filters conjunctively, so a subject carrying several
// digests (e.g. the same commit as both sha1 and gitCommit) is queried one
// digest at a time and the matches are merged.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	if len(subjects) == 0 {
		return c.Fetch(ctx, opts)
	}
	return c.query(ctx, opts, subjectFilters("", subjects))
}

// FetchByPredicateType retrieves the attestations carrying any of the
// predicate types.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, predicateTypes []attestation.PredicateType) ([]attestation.Envelope, error) {
	if len(predicateTypes) == 0 {
		return c.Fetch(ctx, opts)
	}
	filters := make([]*stashclient.Filters, 0, len(predicateTypes))
	for _, pt := range predicateTypes {
		filters = append(filters, &stashclient.Filters{PredicateType: string(pt)})
	}
	return c.query(ctx, opts, filters)
}

// FetchByPredicateTypeAndSubject retrieves the attestations matching any of
// the subjects while carrying any of the predicate types.
func (c *Collector) FetchByPredicateTypeAndSubject(ctx context.Context, opts attestation.FetchOptions, predicateTypes []attestation.PredicateType, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	switch {
	case len(predicateTypes) == 0:
		return c.FetchBySubject(ctx, opts, subjects)
	case len(subjects) == 0:
		return c.FetchByPredicateType(ctx, opts, predicateTypes)
	}
	var filters []*stashclient.Filters
	for _, pt := range predicateTypes {
		filters = append(filters, subjectFilters(string(pt), subjects)...)
	}
	return c.query(ctx, opts, filters)
}

// subjectFilters expands subjects into single-digest stash filters (plus a
// name/uri filter for subjects that carry no digest), each stamped with the
// given predicate type when non-empty. Subjects with nothing filterable are
// skipped rather than matching everything.
func subjectFilters(predicateType string, subjects []attestation.Subject) []*stashclient.Filters {
	var out []*stashclient.Filters
	for _, subject := range subjects {
		if subject == nil {
			continue
		}
		digests := subject.GetDigest()
		if len(digests) == 0 {
			if subject.GetName() == "" && subject.GetUri() == "" {
				continue
			}
			out = append(out, &stashclient.Filters{
				PredicateType: predicateType,
				SubjectName:   subject.GetName(),
				SubjectURI:    subject.GetUri(),
			})
			continue
		}
		for algo, value := range digests {
			out = append(out, &stashclient.Filters{
				PredicateType: predicateType,
				SubjectDigest: map[string]string{algo: value},
			})
		}
	}
	return out
}

// query runs each filter set against stash, merges the matches deduplicated
// by attestation id — the same attestation commonly matches several of the
// expanded filters — and then fetches and parses each raw attestation once.
func (c *Collector) query(ctx context.Context, opts attestation.FetchOptions, filters []*stashclient.Filters) ([]attestation.Envelope, error) {
	var cursor *stashclient.Cursor
	if opts.Limit > 0 {
		cursor = &stashclient.Cursor{Limit: opts.Limit}
	}

	seen := map[string]bool{}
	ids := []string{}
	for _, filter := range filters {
		result, err := c.client.ListAttestations(ctx, c.Options.Org, c.Options.Namespace, filter, cursor)
		if err != nil {
			return nil, fmt.Errorf("listing attestations: %w", err)
		}
		for _, att := range result.Attestations {
			if att == nil || seen[att.ID] {
				continue
			}
			seen[att.ID] = true
			ids = append(ids, att.ID)
		}
	}

	envelopes := make([]attestation.Envelope, 0, len(ids))
	for _, id := range ids {
		raw, err := c.client.GetAttestationRaw(ctx, c.Options.Org, c.Options.Namespace, id)
		if err != nil {
			return nil, fmt.Errorf("getting raw attestation %s: %w", id, err)
		}
		envs, err := c.parsers.Parse(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("parsing attestation %s: %w", id, err)
		}
		if opts.KeepContent {
			envelope.KeepContent(envs, raw)
		}
		envelopes = append(envelopes, envs...)
	}
	if opts.Limit > 0 && len(envelopes) > opts.Limit {
		envelopes = envelopes[:opts.Limit]
	}
	return envelopes, nil
}
