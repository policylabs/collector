// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package filesystem implements an attestation collector from a fs.FS
package filesystem

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/internal/readlimit"
)

var TypeMoniker = "fs"

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithInitString(istr))
}

// DefaultExtensions are the file extensions the collector reads attestations
// from when no other list is configured: bare statements, DSSE envelopes and
// sigstore bundles (json, bundle), JSONL multi-attestation files, SBOM
// documents (spdx, cdx) and policy materials authored in HJSON.
var DefaultExtensions = []string{"json", "jsonl", "spdx", "cdx", "bundle", "hjson"}

func New(opts ...OptFn) (*Collector, error) {
	c := &Collector{
		Extensions:               slices.Clone(DefaultExtensions),
		SignatureExtensions:      append([]string{}, defaultSignatureExtensions...),
		SigstoreBundleExtensions: append([]string{}, defaultSigstoreBundleExtensions...),
		CertificateExtensions:    append([]string{}, defaultCertificateExtensions...),
		RekorURL:                 defaultRekorURL,
		IgnoreOtherFiles:         true,
		Path:                     ".",
	}
	for _, f := range opts {
		if err := f(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// OptFn configures a filesystem collector.
type OptFn func(*Collector) error

var WithInitString = func(s string) OptFn {
	return func(c *Collector) error {
		c.FS = os.DirFS(s)
		return nil
	}
}

var WithFS = func(iofs fs.FS) OptFn {
	return func(c *Collector) error {
		c.FS = iofs
		return nil
	}
}

var WithPath = func(path string) OptFn {
	return func(c *Collector) error {
		c.Path = strings.TrimPrefix(path, "/")
		if c.Path == "" {
			c.Path = "."
		}
		return nil
	}
}

// WithExtensions sets the file extensions (without the dot) the collector
// reads attestations from, replacing DefaultExtensions.
var WithExtensions = func(exts []string) OptFn {
	return func(c *Collector) error {
		c.Extensions = slices.Clone(exts)
		return nil
	}
}

var WithSignatureExtensions = func(exts []string) OptFn {
	return func(c *Collector) error {
		c.SignatureExtensions = exts
		return nil
	}
}

var WithSigstoreBundleExtensions = func(exts []string) OptFn {
	return func(c *Collector) error {
		c.SigstoreBundleExtensions = exts
		return nil
	}
}

var WithCertificateExtensions = func(exts []string) OptFn {
	return func(c *Collector) error {
		c.CertificateExtensions = exts
		return nil
	}
}

var WithRekorURL = func(url string) OptFn {
	return func(c *Collector) error {
		c.RekorURL = url
		return nil
	}
}

var WithKey = func(keys ...key.PublicKeyProvider) OptFn {
	return func(c *Collector) error {
		c.Keys = append(c.Keys, keys...)
		return nil
	}
}

var _ attestation.Fetcher = (*Collector)(nil)

// Collector is the filesystem collector
type Collector struct {
	Extensions               []string
	SignatureExtensions      []string
	SigstoreBundleExtensions []string
	CertificateExtensions    []string
	RekorURL                 string
	IgnoreOtherFiles         bool
	Path                     string
	FS                       fs.FS
	Keys                     []key.PublicKeyProvider
}

// SetKeys sets the verification keys used by the collector.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if c.FS == nil {
		return nil, errors.New("collector has no filesystem defined")
	}

	ret := []attestation.Envelope{}
	var allFiles []string

	// Walk the filesystem and read any attestations
	if err := fs.WalkDir(c.FS, c.Path, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("scanning at %s: %w", path, err)
		}

		// Stop walking once the caller has given up
		if err := ctx.Err(); err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		// Collect all file paths for signature pair processing
		allFiles = append(allFiles, path)

		// Skip files with signature extensions from inline processing.
		// They will be handled by processSignaturePairs after the walk.
		if c.hasSignatureExtension(path) {
			return nil
		}

		if c.IgnoreOtherFiles {
			ext := filepath.Ext(path)
			if !slices.Contains(c.Extensions, strings.TrimPrefix(ext, ".")) {
				return nil
			}
		}

		// Check file size before reading
		maxSize := readlimit.Resolve(opts.MaxReadSize)
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("getting file info for %s: %w", path, err)
		}
		if info.Size() > maxSize {
			return fmt.Errorf("file %s (%d bytes) exceeds max read size (%d bytes)", path, info.Size(), maxSize)
		}

		// Read the file data from the filesystem
		bs, err := fs.ReadFile(c.FS, path)
		if err != nil {
			return fmt.Errorf("reading file from fs: %w", err)
		}

		var attestations []attestation.Envelope

		// Pass the read data to all the enabled parsers, except if the file
		// is a jsonl bundle:
		if strings.HasSuffix(path, ".jsonl") {
			attestations, err = (&envelope.JsonlParser{KeepContent: opts.KeepContent}).Parse(bs)
		} else {
			attestations, err = envelope.Parsers.Parse(bytes.NewReader(bs))
			if err == nil && opts.KeepContent {
				envelope.KeepContent(attestations, bs)
			}
		}
		if err != nil {
			// An unparseable file shouldn't fail the whole collection —
			// log and continue.
			logrus.Debugf("skipping %s: parsing attestations: %v", path, err)
			return nil
		}

		if opts.Query != nil {
			attestations = opts.Query.Run(attestations)
		}
		ret = append(ret, attestations...)

		if opts.Limit > 0 && len(ret) >= opts.Limit {
			ret = ret[:opts.Limit]
			return errLimitReached
		}

		return nil
	}); err != nil && !errors.Is(err, errLimitReached) {
		return nil, fmt.Errorf("scanning filesystem at %s: %w", c.Path, err)
	}

	// Process signature pairs after the walk
	ret = append(ret, c.processSignaturePairs(ctx, allFiles, opts)...)

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// errLimitReached is a sentinel error used to break out of fs.WalkDir
// when the attestation limit has been reached.
var errLimitReached = errors.New("limit reached")

func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	sets := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		sets = append(sets, s.GetDigest())
	}
	filter := filters.SubjectHashMatcher{
		HashSets: sets,
	}

	if opts.Query == nil {
		opts.Query = &attestation.Query{
			Filters: []attestation.Filter{&filter},
		}
	} else {
		opts.Query.Filters = append(opts.Query.Filters, &filter)
	}

	return c.Fetch(ctx, opts)
}

func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	filter := filters.PredicateTypeMatcher{
		PredicateTypes: map[attestation.PredicateType]struct{}{},
	}

	for _, pt := range pts {
		filter.PredicateTypes[pt] = struct{}{}
	}

	if opts.Query == nil {
		opts.Query = &attestation.Query{
			Filters: []attestation.Filter{&filter},
		}
	} else {
		opts.Query.Filters = append(opts.Query.Filters, &filter)
	}

	return c.Fetch(ctx, opts)
}
