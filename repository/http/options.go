// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/url"
	"time"
)

type optFn = func(*Options) error

// Options captures the URLs and templates for the http collector variants.
// The options control the collector variant that gets returned by New()
type Options struct {
	URLs                         []string
	TemplateSubject              string
	TemplateSubjectDigest        string
	TemplateSubjectName          string
	TemplateSubjectUri           string
	TemplatePredicateType        string
	TemplatePredicateTypeSubject string
	Retries                      uint
	ReadJSONL                    bool
	// Timeout bounds each HTTP request, headers and body. The library's
	// default of three seconds is too tight for a release asset served
	// through a redirect to a storage host, which is where attestations
	// published with a release live.
	Timeout time.Duration
}

func (o *Options) CanFetchSubject() bool {
	return o.TemplateSubject != "" || o.TemplateSubjectDigest != "" || o.TemplateSubjectName != ""
}

func (o *Options) CanFetchPredicateType() bool {
	return o.TemplatePredicateType != ""
}

func (o *Options) CanTemplatePredicateTypeSubject() bool {
	return o.TemplatePredicateTypeSubject != ""
}

// WithReadJSONL sets the options to assume the data read will be in linear
// json data.
func WithReadJSONL(doit bool) optFn {
	return func(opts *Options) error {
		opts.ReadJSONL = doit
		return nil
	}
}

// WithRetries fetches the number of retires to read
func WithRetries(num uint) optFn {
	return func(opts *Options) error {
		opts.Retries = num
		return nil
	}
}

// WithTimeout bounds each HTTP request (default DefaultTimeout). Zero or
// negative keeps the default.
func WithTimeout(timeout time.Duration) optFn {
	return func(opts *Options) error {
		if timeout > 0 {
			opts.Timeout = timeout
		}
		return nil
	}
}

// WithURL sets the URl to fetch the data
func WithURL(uriStrings ...string) optFn {
	return func(opts *Options) error {
		for _, s := range uriStrings {
			_, err := url.Parse(s)
			if err != nil {
				return err
			}
		}
		opts.URLs = uriStrings
		return nil
	}
}

func WithTemplateSubject(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubject = templ
		return nil
	}
}

func WithTemplateSubjectDigest(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectDigest = templ
		return nil
	}
}

func WithTemplateSubjectName(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectName = templ
		return nil
	}
}

func WithTemplateSubjectUri(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplateSubjectUri = templ
		return nil
	}
}

func WithTemplatePredicateType(templ string) optFn {
	return func(opts *Options) error {
		opts.TemplatePredicateType = templ
		return nil
	}
}
