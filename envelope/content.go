// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/carabiner-dev/hasher"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/envelope/bare"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/envelope/dsse"
	"github.com/policylabs/collector/statement"
)

// MediaTypeReader is implemented by the envelope parsers that say which media
// types they read. The parsers of this module all do.
type MediaTypeReader interface {
	ReadsMediaType(mediaType string) bool
}

// ForMediaType returns the parser that reads data of a media type, nil when
// there is none. The parsers in the list are asked first, then the bare
// parser, which reads unsigned statements.
//
// It is how the content kept in the origin of an attestation is read back.
// Content a parser reads is the attestation itself and parses again into
// what was evaluated. Content no parser reads, or of no type, is the
// material an attestation was built from: reading it back means
// reassembling the attestation as the repository that kept it did.
func (list *ParserList) ForMediaType(mediaType string) attestation.EnvelopeParser {
	if mediaType == "" {
		return nil
	}
	for _, parser := range *list {
		if r, ok := parser.(MediaTypeReader); ok && r.ReadsMediaType(mediaType) {
			return parser
		}
	}
	if b := bare.New(); b.ReadsMediaType(mediaType) {
		return b
	}
	return nil
}

// IsAttestationMediaType reports if content of a media type is an attestation
// that can be parsed as it is: one of the envelope parsers reads it.
func IsAttestationMediaType(mediaType string) bool {
	return Parsers.ForMediaType(mediaType) != nil
}

// KeepContent records data, the bytes an envelope was parsed from, as the
// content of the origin of its predicate, with its media type. Repositories
// call it when asked to through the KeepContent fetch option, so that a
// consumer can carry the evidence it evaluated along with its results.
//
// The content is only kept when data produced exactly one envelope and the
// parser recorded its origin as a resource descriptor: that is when the
// origin's digest is the digest of data. Anything else is left untouched.
//
// What is kept is always something an envelope parser reads back. Data that
// was not an attestation, a predicate the bare parser wrapped in a statement
// (an SBOM, a scanner report), is kept as that statement and not as it was
// read (see KeepStatement).
func KeepContent(envs []attestation.Envelope, data []byte) {
	if len(envs) != 1 || envs[0] == nil || len(data) == 0 {
		return
	}
	pred := envs[0].GetPredicate()
	if pred == nil {
		return
	}
	rd, ok := pred.GetOrigin().(*intoto.ResourceDescriptor)
	if !ok || rd == nil {
		return
	}

	switch e := envs[0].(type) {
	case *bundle.Envelope:
		rd.Content = data
		// A bundle records the media type it declares
		rd.MediaType = e.GetMediaType()
		if rd.GetMediaType() == "" {
			rd.MediaType = string(FormatBundleV3)
		}
	case *dsse.Envelope:
		rd.Content = data
		rd.MediaType = dsse.MediaType
	case *bare.Envelope:
		// The bare parser reads statements and wraps anything else in one.
		// Asking the statement parsers, as it does, is the only way to tell
		// them apart: they take statements a look at the data would miss.
		if _, err := statement.Parsers.Parse(data); err == nil {
			rd.Content = data
			rd.MediaType = bare.MediaType
			return
		}
		if err := KeepStatement(envs[0]); err != nil {
			logrus.Debugf("not keeping the content of an attestation: %v", err)
		}
	}
}

// KeepStatement records the statement of an unsigned attestation, as it
// serializes, as the content of the origin of its predicate.
//
// It is how a repository keeps an attestation it built itself around data
// that was not one: an SBOM attached to an image, a report read from a file.
// The statement is unsigned, so nothing is lost by keeping it in place of the
// data it wraps, and it reads back as it is, subjects included, where the
// data alone would have to be wrapped again by the same repository.
//
// The digest of the origin becomes the digest of the statement kept, no
// longer that of the data that was read. Its name and URI are left as they
// were: they still say where the data came from.
func KeepStatement(env attestation.Envelope) error {
	if env == nil || env.GetStatement() == nil || env.GetPredicate() == nil {
		return errors.New("attestation has no statement to keep")
	}
	data, err := json.Marshal(env.GetStatement())
	if err != nil {
		return fmt.Errorf("serializing statement: %w", err)
	}
	return KeepData(env, data, bare.MediaType)
}

// KeepData records data as the content of the origin of an attestation's
// predicate, with its media type, and makes the digest of the origin the
// digest of data.
//
// It is for the repositories that do not read an attestation as one piece of
// data, where KeepContent has nothing to keep: they build the envelope from
// several (a signed payload in one place and what verifies it in another)
// and keep it as they serialize it, or as the piece that is the attestation.
// The data must be what the media type says, so that it reads back.
//
// The name and URI of the origin are left as they were: they still say where
// the attestation came from. An attestation without an origin gets one.
func KeepData(env attestation.Envelope, data []byte, mediaType string) error {
	if env == nil || env.GetPredicate() == nil {
		return errors.New("attestation has no predicate to keep content for")
	}
	if len(data) == 0 {
		return errors.New("no data to keep")
	}
	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return fmt.Errorf("hashing content: %w", err)
	}
	kept := digests.ToResourceDescriptors()[0]

	rd, ok := env.GetPredicate().GetOrigin().(*intoto.ResourceDescriptor)
	if !ok || rd == nil {
		rd = &intoto.ResourceDescriptor{}
		env.GetPredicate().SetOrigin(rd)
	}
	rd.Digest = kept.GetDigest()
	rd.Content = data
	rd.MediaType = mediaType
	return nil
}

// OriginContent returns the content kept in the origin of a predicate, nil
// when there is none. A repository that replaces the origin a parser set
// (to name where the attestation was read from) uses it to carry the content
// over to the new one.
func OriginContent(pred attestation.Predicate) []byte {
	if pred == nil {
		return nil
	}
	rd, ok := pred.GetOrigin().(*intoto.ResourceDescriptor)
	if !ok || rd == nil {
		return nil
	}
	return rd.GetContent()
}
