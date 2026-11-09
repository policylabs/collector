// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package http implements an attestations collector that reads
// data from an https endpoint.
package http

import (
	"context"
	"strings"
	"time"

	"github.com/policylabs/attestation"
)

var (
	TypeMoniker      = "http"
	TypeMonikerHTTPS = "https"
)

// Implement the factory function
var BuildHTTP = func(uriString string) (attestation.Repository, error) {
	if strings.HasPrefix(uriString, "//") {
		uriString = "http:" + uriString
	}
	return New(WithURL(uriString))
}

var BuildHTTPs = func(uriString string) (attestation.Repository, error) {
	if strings.HasPrefix(uriString, "//") {
		uriString = "https:" + uriString
	}
	return New(WithURL(uriString))
}

// Ensure the collector variants implement the interfaces
var (
	_ attestation.Fetcher = (*Collector)(nil)
	_ attestation.Fetcher = (*CollectorSubject)(nil)
	_ attestation.Fetcher = (*CollectorPredicateType)(nil)
	_ attestation.Fetcher = (*CollectorSubjectAndType)(nil)
)

var (
	_ attestation.FetcherByPredicateType = (*CollectorPredicateType)(nil)
	_ attestation.FetcherByPredicateType = (*CollectorSubjectAndType)(nil)
)

var (
	_ attestation.FetcherBySubject = (*CollectorSubject)(nil)
	_ attestation.FetcherBySubject = (*CollectorSubjectAndType)(nil)
)

type CollectorPredicateTypeSubject struct {
	Options Options
}

// DefaultTimeout bounds each attempt of an HTTP request. A timed-out attempt
// is retried (Retries, three by default, with backoff), so a slow host gets
// several chances while a dead one fails within about a minute.
const DefaultTimeout = 15 * time.Second

var defaultOptions = Options{
	Timeout:   DefaultTimeout,
	Retries:   3,
	ReadJSONL: true,
}

// New creates a new collector. The type of collector returned varies according
// to the specified URL templates.
func New(funcs ...optFn) (attestation.Fetcher, error) {
	opts := defaultOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	// Return the collector according to the defined capabilities
	switch {
	case opts.CanFetchPredicateType() && !opts.CanFetchSubject() && !opts.CanTemplatePredicateTypeSubject():
		return &CollectorPredicateType{
			Options: opts,
		}, nil
	case !opts.CanFetchPredicateType() && opts.CanFetchSubject() && !opts.CanTemplatePredicateTypeSubject():
		return &CollectorSubject{
			Options: opts,
		}, nil
	case opts.CanFetchPredicateType() && opts.CanFetchSubject() && !opts.CanTemplatePredicateTypeSubject():
		return &CollectorSubjectAndType{
			Options: opts,
		}, nil
	default:
		return &Collector{
			Options: opts,
		}, nil
	}
}

// Collector is the general collector that supports fetching from a single URL
type Collector struct {
	Options Options
}

func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return fetchGeneral(ctx, &c.Options, opts)
}

// CollectorSubjectAndType implements the attestation.FetcherBySubject and attestation.FetcherByPredicateType interfaces
// it is not the same as the PredicateTypeSubject interface
type CollectorSubjectAndType struct {
	Options Options
}

func (c *CollectorSubjectAndType) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return fetchGeneral(ctx, &c.Options, opts)
}

func (c *CollectorSubjectAndType) FetchBySubject(ctx context.Context, fo attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	return fetchBySubject(ctx, &c.Options, fo, subjects)
}

func (c *CollectorSubjectAndType) FetchByPredicateType(ctx context.Context, fo attestation.FetchOptions, types []attestation.PredicateType) ([]attestation.Envelope, error) {
	return fetchByPredicateType(ctx, &c.Options, fo, types)
}

// CollectorSubject implements the attestation.FetcherBySubject interface
type CollectorSubject struct {
	Options Options
}

func (c *CollectorSubject) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return fetchGeneral(ctx, &c.Options, opts)
}

func (c *CollectorSubject) FetchBySubject(ctx context.Context, fo attestation.FetchOptions, subjects []attestation.Subject) ([]attestation.Envelope, error) {
	return fetchBySubject(ctx, &c.Options, fo, subjects)
}

// CollectorPredicateType implements the attestation.FetcherByPredicateType interface
type CollectorPredicateType struct {
	Options Options
}

func (c *CollectorPredicateType) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return fetchGeneral(ctx, &c.Options, opts)
}

func (c *CollectorPredicateType) FetchByPredicateType(ctx context.Context, fo attestation.FetchOptions, types []attestation.PredicateType) ([]attestation.Envelope, error) {
	return fetchByPredicateType(ctx, &c.Options, fo, types)
}

func (c *CollectorPredicateTypeSubject) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return fetchGeneral(ctx, &c.Options, opts)
}
