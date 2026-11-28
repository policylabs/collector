// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"os"

	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
)

// DefaultMaxReadSize is the default maximum number of bytes the collector will
// read from any single external source (7 MiB).
const DefaultMaxReadSize int64 = 7 << 20

var defaultOptions = Options{
	UserAgentString:  "carabiner-collector/v1",
	FailIfNoFetchers: false,
	UseCache:         true,
	ParallelFetches:  4,
	ParallelStores:   4,
	MaxReadSize:      DefaultMaxReadSize,
	Fetch:            attestation.FetchOptions{},
	Store:            attestation.StoreOptions{},
}

// Options groups the configuration knob for the collector agent
type Options struct {
	UserAgentString string

	// FailIfNoFetchers Return an error when fetching if no repos are configured (instead of just nil)
	FailIfNoFetchers bool

	// Use cache controls if the agent uses the attestation cache
	UseCache bool

	ParallelFetches int
	ParallelStores  int

	// MaxReadSize is the maximum number of bytes the collector will read from
	// any single external source (HTTP response, file, OCI blob, etc.).
	// A value of 0 means no limit. Defaults to DefaultMaxReadSize (7 MiB).
	MaxReadSize int64

	Fetch attestation.FetchOptions
	Store attestation.StoreOptions

	// Keys are verification keys that the agent distributes to repositories
	// implementing the repository.SignatureVerifier interface.
	Keys []key.PublicKeyProvider
}

type InitFunction func(*Agent) error

func WithRepository(repo attestation.Repository) InitFunction {
	return func(agent *Agent) error {
		return agent.AddRepository(repo)
	}
}

func WithParallelFetches(threads int) InitFunction {
	return func(agent *Agent) error {
		agent.Options.ParallelFetches = threads
		return nil
	}
}

func WithParallelStores(threads int) InitFunction {
	return func(agent *Agent) error {
		agent.Options.ParallelStores = threads
		return nil
	}
}

// WithMaxReadSize sets the maximum number of bytes the collector will read from
// any single external source. A value of 0 means no limit.
func WithMaxReadSize(n int64) InitFunction {
	return func(agent *Agent) error {
		agent.Options.MaxReadSize = n
		return nil
	}
}

// FetchOptionsFunc are functions to define options when fetching
type FetchOptionsFunc func(*attestation.FetchOptions)

// WithQuery passes a query to the options set
func WithQuery(q *attestation.Query) FetchOptionsFunc {
	return func(opts *attestation.FetchOptions) {
		opts.Query = q
	}
}

// WithLimit sets the maximum number of attestations to be returned by the agent
func WithLimit(n int) FetchOptionsFunc {
	return func(o *attestation.FetchOptions) {
		o.Limit = n
	}
}

// WithKeepContent asks the repositories to keep the data of each attestation,
// as it was read, in the content of its predicate's origin.
func WithKeepContent(keep bool) FetchOptionsFunc {
	return func(o *attestation.FetchOptions) {
		o.KeepContent = keep
	}
}

// WithKeys registers verification keys at the agent level. Before each fetch,
// the agent distributes these keys to any repository that implements repository.SignatureVerifier.
func WithKeys(keys ...key.PublicKeyProvider) InitFunction {
	return func(agent *Agent) error {
		agent.Options.Keys = append(agent.Options.Keys, keys...)
		return nil
	}
}

// WithKeyFiles reads public keys from the given file paths and registers them
// at the agent level. Each file is tried first as a GPG public key, then as a
// PEM public key. An error is returned if any file cannot be parsed.
func WithKeyFiles(paths ...string) InitFunction {
	return func(agent *Agent) error {
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				return fmt.Errorf("reading key file %q: %w", p, err)
			}

			// Try GPG first
			gpgKeys, err := key.ParseGPGPublicKey(data)
			if err == nil && len(gpgKeys) > 0 {
				for _, k := range gpgKeys {
					agent.Options.Keys = append(agent.Options.Keys, k)
				}
				continue
			}

			// Fall back to PEM
			pub, err := key.NewParser().ParsePublicKey(data)
			if err == nil {
				agent.Options.Keys = append(agent.Options.Keys, pub)
				continue
			}

			return fmt.Errorf("unable to parse key file %q as GPG or PEM", p)
		}
		return nil
	}
}

// StoreOptionsFunc are functions to define options when fetching
type StoreOptionsFunc func(*attestation.StoreOptions)
