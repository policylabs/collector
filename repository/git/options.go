// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package jsonl implements an attestations collector that reads
// from files using the JSON Lines (jsonl) format.

package git

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/carabiner-dev/vcslocator"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

type optFn = func(*Options) error

type Options struct {
	URL    string
	Path   string
	Ref    string
	Commit string

	// Extensions are the file extensions read from the cloned repository.
	// When nil, the filesystem collector's defaults are used.
	Extensions []string

	// Auth authenticates every request to the remote: resolving the ref,
	// cloning it and fetching the commits a subject query asks about. Nil
	// reads anonymously, which is all a public repository needs.
	Auth transport.AuthMethod
}

var defaultOptions = Options{}

func (o *Options) Validate() error {
	return nil
}

func WithLocator(init string) optFn {
	return func(opts *Options) error {
		// Detect plain local filesystem paths (including Windows paths like
		// C:\foo\bar) and rewrite them as file:// locators before URL parsing.
		// Without this, url.Parse treats the Windows drive letter as a scheme
		// and mangles the path.
		if isLocalPath(init) {
			head, tail := init, ""
			if i := strings.IndexAny(init, "@#"); i >= 0 {
				head, tail = init[:i], init[i:]
			}
			init = string(vcslocator.NewFromPath(head)) + tail
		}

		u, err := url.Parse(init)
		if err != nil {
			return fmt.Errorf("parsing url: %w", err)
		}
		path, branch, ok := strings.Cut(u.Path, "@")
		sch := u.Scheme
		if sch != "" {
			sch += "://"
		}
		opts.URL = sch + u.Hostname() + path
		if ok {
			opts.Ref = branch
		}
		opts.Path = u.Fragment
		return nil
	}
}

// isLocalPath reports whether s is a filesystem path rather than a URL. It
// treats anything without a recognized transport scheme as a local path.
func isLocalPath(s string) bool {
	for _, p := range []string{"http://", "https://", "ssh://", "file://", "git+http://", "git+https://", "git+ssh://", "git+file://"} {
		if strings.HasPrefix(s, p) {
			return false
		}
	}
	return true
}

func WithPath(path string) optFn {
	return func(opts *Options) error {
		opts.Path = path
		return nil
	}
}

// WithAuth authenticates the requests to the remote with a go-git transport
// auth method, which is what reading a private repository takes. An init
// string cannot carry credentials, so a caller that holds them builds the
// collector with New and this option.
func WithAuth(auth transport.AuthMethod) optFn {
	return func(opts *Options) error {
		opts.Auth = auth
		return nil
	}
}

// WithToken authenticates the requests to the remote with a bearer or
// installation token, using GitHub's "x-access-token" basic-auth
// convention, as the gitsign collector does. An empty token leaves the
// collector reading anonymously.
func WithToken(token string) optFn {
	return func(opts *Options) error {
		if token != "" {
			opts.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
		}
		return nil
	}
}

// WithExtensions sets the file extensions (without the dot) attestations are
// read from in the cloned repository, replacing the filesystem defaults.
func WithExtensions(exts []string) optFn {
	return func(opts *Options) error {
		opts.Extensions = exts
		return nil
	}
}
