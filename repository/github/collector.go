// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package github implements a collector that reads from the GitHub attestations
// store.
package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	gh "github.com/carabiner-dev/github"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/internal/readlimit"
	"github.com/policylabs/collector/repository"
)

const (
	// Endpoint to store attestation
	gitHubAttestationsUploadEndpoint = `repos/%s/%s/attestations`
	TypeMoniker                      = "github"
)

// Ensure the collector implements the interfaces
var (
	_ attestation.Fetcher          = (*Collector)(nil)
	_ attestation.FetcherBySubject = (*Collector)(nil)
	_ attestation.Storer           = (*Collector)(nil)
)

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithRepo(istr))
}

type Collector struct {
	Options Options
	client  *gh.Client
}

type Options struct {
	Owner string
	Repo  string
	// Access token (uses GITHUB_TOKEN if unset)
	Token string
}

type optFn = func(*Options)

func WithInit(init string) optFn {
	return WithRepo(strings.TrimPrefix(init, TypeMoniker+":"))
}

func WithToken(token string) optFn {
	return func(opts *Options) {
		opts.Token = token
	}
}

func WithOwner(owner string) optFn {
	return func(opts *Options) {
		opts.Owner = owner
	}
}

func WithRepo(repo string) optFn {
	return func(opts *Options) {
		// Tolerate repository URLs and slugs prefixed with the host
		for _, prefix := range []string{"https://github.com/", "http://github.com/", "github.com/"} {
			repo = strings.TrimPrefix(repo, prefix)
		}
		repo = strings.TrimSuffix(strings.TrimSuffix(repo, "/"), ".git")
		owner, r, sino := strings.Cut(repo, "/")
		if sino {
			opts.Owner = owner
			opts.Repo = r
		} else {
			opts.Repo = repo
		}
	}
}

// New returns a new collector
func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := Options{}
	for _, fn := range funcs {
		fn(&opts)
	}

	c, err := gh.NewClient(gh.WithToken(opts.Token))
	if err != nil {
		return nil, err
	}
	return &Collector{
		Options: opts,
		client:  c,
	}, nil
}

type attResponse struct {
	Attestations []struct {
		Bundle       json.RawMessage `json:"bundle"`
		RepositoryID int64           `json:"repository_id"`
		BundleURL    string          `json:"bundle_url"`
	} `json:"attestations"`
}

// fetchedEnvelope pairs an envelope read from the API with a key that
// identifies the attestation across responses.
type fetchedEnvelope struct {
	envelope attestation.Envelope
	key      string
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	return nil, attestation.ErrFetcherMethodNotImplemented
}

// FetchBySubject is the only method supported as the GitHub api can only list
// attestations by subject.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	if c.Options.Owner == "" && c.Options.Repo == "" {
		return nil, fmt.Errorf("missing repository data")
	}

	// Build a list of subjects to query. The GitHub API looks attestations
	// up by the literal algo:value digest string, without restricting the
	// algorithm, so every digest of the subjects is queried.
	subjects := map[string]string{}
	for _, s := range subj {
		for algo, value := range s.GetDigest() {
			subjects[fmt.Sprintf("%s:%s", strings.ToLower(algo), value)] = s.GetName()
		}
	}
	ret := []attestation.Envelope{}
	// A subject with several digests returns the same attestation once
	// per digest, keep track of what was already read.
	seen := map[string]struct{}{}
	// Get all the attestations up to the configured limit
	for digest := range subjects {
		url := fmt.Sprintf("users/%s/attestations/%s", c.Options.Owner, digest)
		if c.Options.Repo != "" {
			url = fmt.Sprintf("/repos/%s/%s/attestations/%s", c.Options.Owner, c.Options.Repo, digest)
		}

		envs, _, err := c.fetchFromUrl(ctx, url, opts)
		if err != nil {
			return nil, fmt.Errorf("fetching attestations: %w", err)
		}
		for _, fe := range envs {
			if _, ok := seen[fe.key]; ok {
				continue
			}
			seen[fe.key] = struct{}{}
			ret = append(ret, fe.envelope)
		}

		if opts.Limit > 0 && len(ret) >= opts.Limit {
			return ret[:opts.Limit], nil
		}
	}
	return ret, nil
}

// fetchFromUrl fetches a page of attestations from the GitHub api. At some point
// this will return true in the boolean if more requests are needed.
//
//nolint:unparam
func (c *Collector) fetchFromUrl(ctx context.Context, url string, opts attestation.FetchOptions) ([]fetchedEnvelope, bool, error) {
	ret := []fetchedEnvelope{}

	// Call the API:
	resp, err := c.client.Call(ctx, http.MethodGet, url, nil)
	if err != nil {
		// If we get a 404 here, it means there are no attestations.
		// TODO(puerco): Use an HTTP error
		if strings.Contains(err.Error(), "HTTP Error 404") {
			return ret, false, nil
		}
		return nil, false, err
	}
	defer resp.Body.Close() //nolint:errcheck
	res := &attResponse{}

	dec := json.NewDecoder(readlimit.Reader(resp.Body, opts.MaxReadSize))
	if err := dec.Decode(res); err != nil {
		return nil, false, fmt.Errorf("parsing response: %w", err)
	}

	for _, e := range res.Attestations {
		if len(e.Bundle) == 0 {
			logrus.Debugf("github: attestation without inline bundle, skipping (%s)", e.BundleURL)
			continue
		}
		// Parse through the bundle parser so the envelope origin is set
		parsed, err := (&bundle.Parser{}).Parse(e.Bundle)
		if err != nil {
			return nil, false, fmt.Errorf("parsing attestation bundle: %w", err)
		}
		if opts.KeepContent {
			envelope.KeepContent(parsed, e.Bundle)
		}
		// Key the attestation on the bundle bytes as served, the same
		// attestation is returned for every digest of its subject.
		sum := sha256.Sum256(e.Bundle)
		for _, env := range parsed {
			ret = append(ret, fetchedEnvelope{envelope: env, key: hex.EncodeToString(sum[:])})
		}
	}
	return ret, false, nil
}

type uploadRequestValueParsed struct {
	Bundle preParsedBundle `json:"bundle"`
}

type preParsedBundle []byte

func (ppb preParsedBundle) MarshalJSON() ([]byte, error) {
	return ppb, nil
}

// Store implements the attestations.Storer interface. Every envelope is
// uploaded on its own, and one failing does not stop the rest: when any
// of them cannot be stored the returned error is a *repository.StoreError
// listing the failed ones, while the others stay stored.
func (c *Collector) Store(ctx context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	serr := repository.NewStoreError()
	for i, env := range envelopes {
		if err := c.storeEnvelope(ctx, env); err != nil {
			serr.Failed[i] = err
			continue
		}
		serr.Stored++
	}
	return serr.ErrorOrNil()
}

// storeEnvelope uploads a single envelope to the attestations store.
func (c *Collector) storeEnvelope(ctx context.Context, env attestation.Envelope) error {
	envelopeData, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling envelope data: %w", err)
	}

	payload := uploadRequestValueParsed{
		Bundle: preParsedBundle(envelopeData),
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	res, err := c.client.Call(
		ctx, http.MethodPost,
		fmt.Sprintf(gitHubAttestationsUploadEndpoint, c.Options.Owner, c.Options.Repo),
		bytes.NewReader(payloadData),
	)
	if err != nil {
		return fmt.Errorf("uploading attestation bundle: %w", err)
	}
	res.Body.Close() //nolint:errcheck,gosec
	return nil
}
