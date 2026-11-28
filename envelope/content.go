// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"encoding/json"
	"strings"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/envelope/bare"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/envelope/dsse"
	"github.com/policylabs/collector/statement"
)

// Media types recorded with the content kept in the origin of an attestation.
// They tell whoever reads the content back what to do with it.
//
// Content of one of the attestation media types (see IsAttestationMediaType)
// is the attestation itself and parses again into what was evaluated.
// Content of any other type is the material an attestation was built from:
// reading it back means reassembling the attestation as the repository that
// kept it did.
const (
	// MediaTypeBundle is the type of a sigstore bundle. The bundle formats
	// are versioned: bundles carry their own media type and it is what gets
	// recorded, this is the prefix they share.
	MediaTypeBundle = "application/vnd.dev.sigstore.bundle"

	// MediaTypeDSSE is the type of a DSSE envelope.
	MediaTypeDSSE = "application/vnd.dsse.envelope.v1+json"

	// MediaTypeInToto is the type of an unsigned in-toto statement.
	MediaTypeInToto = "application/vnd.in-toto+json"

	// MediaTypeJSON is the type recorded for JSON data that is not an
	// attestation: a predicate (an SBOM, a scanner report) the parser
	// wrapped in a statement of its own.
	MediaTypeJSON = "application/json"
)

// IsAttestationMediaType reports if content of a media type is an attestation
// that can be parsed as it is: a sigstore bundle, a DSSE envelope or an
// in-toto statement. Content of any other type, or of none, has to be
// reassembled into the attestation it was kept for.
func IsAttestationMediaType(mediaType string) bool {
	return mediaType == MediaTypeDSSE || mediaType == MediaTypeInToto ||
		strings.HasPrefix(mediaType, MediaTypeBundle)
}

// contentMediaType returns the media type of the data an envelope was parsed
// from, empty when it cannot tell.
func contentMediaType(env attestation.Envelope, data []byte) string {
	switch e := env.(type) {
	case *bundle.Envelope:
		if mt := e.GetMediaType(); mt != "" {
			return mt
		}
		return string(FormatBundleV3)
	case *dsse.Envelope:
		return MediaTypeDSSE
	case *bare.Envelope:
		// The bare parser reads statements and wraps anything else in one.
		// Asking the statement parsers, as it does, is the only way to tell
		// them apart: they take statements a look at the data would miss.
		if _, err := statement.Parsers.Parse(data); err == nil {
			return MediaTypeInToto
		}
		if json.Valid(data) {
			return MediaTypeJSON
		}
	}
	return ""
}

// KeepContent records data, the bytes an envelope was parsed from, as the
// content of the origin of its predicate. Repositories call it when asked to
// through the KeepContent fetch option, so that a consumer can carry the
// evidence it evaluated along with its results.
//
// The content is only kept when data produced exactly one envelope and the
// parser recorded its origin as a resource descriptor: that is when the
// origin's digest is the digest of data. Anything else is left untouched.
//
// The media type of the data is recorded with it (see the MediaType
// constants).
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
	rd.Content = data
	rd.MediaType = contentMediaType(envs[0], data)
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
