// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package pypi implements a collector that reads PEP 740 attestations from
// a Python package index. Each distribution file of a release is looked up
// through the index's integrity API and every attestation in its provenance
// object is returned as a verifiable sigstore bundle.
package pypi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	gopurl "github.com/package-url/packageurl-go"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/internal/readlimit"
)

var TypeMoniker = "pypi"

// Build is the factory function used to register the collector. The init
// string is a PyPI purl, e.g. "pkg:pypi/sampleproject@4.0.0". An empty
// string builds a global-mode collector driven by the subjects it is asked
// for.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPackageURL(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

// provenanceMediaType is the content type of the integrity API responses.
const provenanceMediaType = "application/vnd.pypi.integrity.v1+json"

const requestTimeout = 60 * time.Second

// Collector reads PEP 740 provenance from a package index.
type Collector struct {
	Options Options
	client  *http.Client
}

// New creates a new PyPI collector.
func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{
		Options: defaultOptions,
		client:  &http.Client{Timeout: requestTimeout},
	}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}
	return c, nil
}

// Fetch retrieves the attestations of every distribution file addressed by
// the configured package URL. A purl with a version reads that release, one
// without reads the latest release, and one with a file_name qualifier
// reads that single file. In global mode (no package URL) it returns
// nothing; use FetchBySubject instead.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if !c.Options.HasPackageURL() {
		return nil, nil
	}
	return c.fetchForPurl(ctx, opts, &c.Options.PackageURL)
}

// fetchForPurl resolves the distribution files a purl addresses and reads
// the provenance of each. Files without provenance are skipped.
func (c *Collector) fetchForPurl(ctx context.Context, opts attestation.FetchOptions, purl *gopurl.PackageURL) ([]attestation.Envelope, error) {
	dists, err := c.resolveDistributions(ctx, opts, purl)
	if err != nil {
		return nil, err
	}

	var ret []attestation.Envelope
	for i := range dists {
		prov, err := c.fetchProvenance(ctx, opts, &dists[i])
		if err != nil {
			return nil, err
		}
		if prov == nil {
			logrus.Debugf("pypi: no provenance for %s", dists[i].Filename)
			continue
		}
		envs, err := prov.Envelopes(&dists[i])
		if err != nil {
			return nil, fmt.Errorf("reading provenance of %s: %w", dists[i].Filename, err)
		}
		if opts.KeepContent {
			for _, env := range envs {
				if err := keepBundle(env, &dists[i]); err != nil {
					return nil, fmt.Errorf("keeping provenance of %s: %w", dists[i].Filename, err)
				}
			}
		}
		ret = append(ret, envs...)
	}

	if opts.Query != nil {
		ret = opts.Query.Run(ret)
	}
	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}
	return ret, nil
}

// FetchBySubject collects attestations for each subject. In configured
// mode it fetches once for the configured purl; in global mode it extracts
// PyPI purls from the subjects' URI and name fields and fetches for each.
// When any subject carries digests, the results are filtered to those
// matching them; purl-only subjects return everything their purl resolves.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	var all []attestation.Envelope

	if c.Options.HasPackageURL() {
		envs, err := c.Fetch(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = envs
	} else {
		purls := extractPurls(subj)
		for i := range purls {
			envs, err := c.fetchForPurl(ctx, opts, &purls[i])
			if err != nil {
				// A missing or unreachable package for one subject shouldn't
				// fail the whole query — log and continue.
				logrus.Debugf("pypi: skipping %s: %v", purls[i].String(), err)
				continue
			}
			all = append(all, envs...)
		}
	}

	hashSets := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		if len(s.GetDigest()) > 0 {
			hashSets = append(hashSets, s.GetDigest())
		}
	}
	if len(hashSets) == 0 {
		return all, nil
	}

	return attestation.NewQuery().WithFilter(&filters.SubjectHashMatcher{
		HashSets: hashSets,
	}).Run(all), nil
}

// FetchByPredicateType handles collecting by predicate type. It requires
// a configured package URL — global mode is subject-driven and has no
// per-predicate-type entry point.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	if !c.Options.HasPackageURL() {
		return nil, nil
	}
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	m := map[attestation.PredicateType]struct{}{}
	for _, pt := range pts {
		m[pt] = struct{}{}
	}

	return attestation.NewQuery().WithFilter(&filters.PredicateTypeMatcher{
		PredicateTypes: m,
	}).Run(all), nil
}

// extractPurls reads PyPI package URLs from the Uri and Name fields of the
// provided subjects. Non-PyPI or unparseable purls are ignored and
// duplicates are removed.
func extractPurls(subjects []attestation.Subject) []gopurl.PackageURL {
	seen := map[string]struct{}{}
	var ret []gopurl.PackageURL
	for _, s := range subjects {
		for _, candidate := range []string{s.GetUri(), s.GetName()} {
			if !strings.HasPrefix(candidate, "pkg:") {
				continue
			}
			p, err := parsePurl(candidate)
			if err != nil {
				continue
			}
			id := p.String()
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ret = append(ret, p)
		}
	}
	return ret
}

// releaseInfo is the subset of the index JSON API response the collector
// needs: the resolved version and the release's files.
type releaseInfo struct {
	Info struct {
		Version string `json:"version"`
	} `json:"info"`
	URLs []struct {
		Filename    string `json:"filename"`
		PackageType string `json:"packagetype"`
		URL         string `json:"url"`
	} `json:"urls"`
}

// resolveDistributions lists the distribution files a purl addresses. A
// file_name qualifier names one file directly; otherwise the release (the
// latest one when the purl has no version) is listed through the JSON API.
func (c *Collector) resolveDistributions(ctx context.Context, opts attestation.FetchOptions, purl *gopurl.PackageURL) ([]Distribution, error) {
	if filename := purl.Qualifiers.Map()[fileNameQualifier]; filename != "" {
		return []Distribution{{
			Project:  purl.Name,
			Version:  purl.Version,
			Filename: filename,
			Index:    c.Options.IndexURL,
		}}, nil
	}

	u := c.Options.IndexURL + "/pypi/" + url.PathEscape(purl.Name)
	if purl.Version != "" {
		u += "/" + url.PathEscape(purl.Version)
	}
	u += "/json"

	data, err := c.get(ctx, u, "application/json", opts.MaxReadSize)
	if err != nil {
		return nil, fmt.Errorf("listing release %s: %w", purl.String(), err)
	}
	if data == nil {
		return nil, fmt.Errorf("release %s not found in %s", purl.String(), c.Options.IndexURL)
	}

	release := &releaseInfo{}
	if err := json.Unmarshal(data, release); err != nil {
		return nil, fmt.Errorf("decoding release listing: %w", err)
	}

	ret := make([]Distribution, 0, len(release.URLs))
	for _, f := range release.URLs {
		ret = append(ret, Distribution{
			Project:     purl.Name,
			Version:     release.Info.Version,
			Filename:    f.Filename,
			PackageType: f.PackageType,
			URL:         f.URL,
			Index:       c.Options.IndexURL,
		})
	}
	return ret, nil
}

// fetchProvenance reads the provenance object of a distribution file from
// the integrity API. It returns nil when the index has no provenance for
// the file.
func (c *Collector) fetchProvenance(ctx context.Context, opts attestation.FetchOptions, dist *Distribution) (*Provenance, error) {
	u := fmt.Sprintf(
		"%s/integrity/%s/%s/%s/provenance", c.Options.IndexURL,
		url.PathEscape(dist.Project), url.PathEscape(dist.Version), url.PathEscape(dist.Filename),
	)
	data, err := c.get(ctx, u, provenanceMediaType, opts.MaxReadSize)
	if err != nil {
		return nil, fmt.Errorf("fetching provenance of %s: %w", dist.Filename, err)
	}
	if data == nil {
		return nil, nil
	}
	prov, err := ParseProvenance(data)
	if err != nil {
		return nil, fmt.Errorf("provenance of %s: %w", dist.Filename, err)
	}
	return prov, nil
}

// get performs a GET request and returns the response body, capped at the
// read limit. A 404 yields a nil body and no error; any other non-200
// status is an error.
func (c *Collector) get(ctx context.Context, u, accept string, maxReadSize int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", accept)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", u, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only body

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("requesting %s: unexpected status %s", u, resp.Status)
	}

	data, err := io.ReadAll(readlimit.Reader(resp.Body, maxReadSize))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", u, err)
	}
	if len(data) == 0 {
		return nil, errors.New("empty response from " + u)
	}
	return data, nil
}
