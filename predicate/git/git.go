// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package git defines the predicates that describe a git object as it is:
// a commit and an annotated tag. They carry the object's own fields and
// nothing else, so an attestation of either type says "this is what the
// object stores" and lets a policy connect objects to one another: a tag to
// the commit it points at, a commit to its tree and parents, and any of them
// to what their message trailers name. Who signed the object is not part of
// the predicate; it is the attestation's verification, filled by whoever
// synthesizes the attestation after checking the object's signature.
//
// The types are deliberately not gitsign's. A gitsign predicate states that
// gitsign signed the object; these state what the object contains, signed or
// not, by anyone.
package git

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/predicate/generic"
)

var (
	// PredicateTypeCommit describes a commit object.
	PredicateTypeCommit = attestation.PredicateType("https://carabiner.dev/git/commit/v0")
	// PredicateTypeTag describes an annotated tag object.
	PredicateTypeTag = attestation.PredicateType("https://carabiner.dev/git/tag/v0")
)

// Identity is a name, an email and a time, as git records an author, a
// committer or a tagger.
type Identity struct {
	Name  string    `json:"name,omitempty"`
	Email string    `json:"email,omitempty"`
	Date  time.Time `json:"date,omitzero"`
}

// Commit is the content of a commit object.
type Commit struct {
	// Tree is the sha of the tree the commit snapshots.
	Tree string `json:"tree"`
	// Parents are the shas of the parent commits, in the commit's order.
	Parents []string `json:"parents,omitempty"`
	// Author and Committer are the identities the commit records.
	Author    *Identity `json:"author,omitempty"`
	Committer *Identity `json:"committer,omitempty"`
	// Message is the commit message, verbatim.
	Message string `json:"message,omitempty"`
	// Trailers are the message's trailers (see ParseTrailers), keyed by
	// token; a token that repeats lists its values in message order.
	Trailers Trailers `json:"trailers,omitempty"`
}

// Tag is the content of an annotated tag object.
type Tag struct {
	// Object is the sha of the object the tag points at and ObjectType its
	// git type ("commit", "tag", "tree", "blob").
	Object     string `json:"object"`
	ObjectType string `json:"objectType,omitempty"`
	// Name is the tag's name as stored in the object (without refs/tags/).
	Name string `json:"name"`
	// Tagger is the identity the tag records.
	Tagger *Identity `json:"tagger,omitempty"`
	// Message is the tag message, verbatim.
	Message string `json:"message,omitempty"`
	// Trailers are the message's trailers (see ParseTrailers).
	Trailers Trailers `json:"trailers,omitempty"`
}

// Trailers maps a trailer token to its values, in message order.
type Trailers map[string][]string

// Get returns the first value of a trailer, or "" when it is absent.
func (t Trailers) Get(token string) string {
	if v := t[token]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// trailerLine matches a trailer: a token of letters, digits and dashes, a
// colon, and the value.
var trailerLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9-]*):[ \t]*(.*)$`)

// ParseTrailers reads a message's trailers as git defines them: the last
// paragraph of the message, when every line in it is a trailer ("Token:
// value") or a continuation line (starting with whitespace) of the trailer
// before it, and when it is not the message's only paragraph. Anything else
// yields nil. The parser attaches no meaning to any token; what a token
// means is the business of whoever wrote it and of the policy reading it.
func ParseTrailers(message string) Trailers {
	paragraphs := strings.Split(strings.TrimRight(strings.ReplaceAll(message, "\r\n", "\n"), "\n"), "\n\n")
	if len(paragraphs) < 2 {
		return nil
	}
	block := strings.Split(strings.Trim(paragraphs[len(paragraphs)-1], "\n"), "\n")
	trailers := Trailers{}
	var lastToken string
	for _, line := range block {
		if lastToken != "" && (strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")) {
			values := trailers[lastToken]
			values[len(values)-1] += "\n" + strings.TrimSpace(line)
			continue
		}
		m := trailerLine.FindStringSubmatch(line)
		if m == nil {
			return nil
		}
		lastToken = m[1]
		trailers[lastToken] = append(trailers[lastToken], strings.TrimSpace(m[2]))
	}
	if len(trailers) == 0 {
		return nil
	}
	return trailers
}

// Parser parses commit and tag predicates.
type Parser struct{}

// New returns a parser for both predicate types.
func New() *Parser { return &Parser{} }

// SupportsType reports whether one of the types is a git object predicate.
func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	return slices.Contains(predTypes, PredicateTypeCommit) || slices.Contains(predTypes, PredicateTypeTag)
}

// Parse reads a commit or a tag predicate. A commit names a tree; a tag
// names an object. Data that is neither is reported as not the right
// format, so the next parser gets a turn.
func (*Parser) Parse(data []byte) (attestation.Predicate, error) {
	var probe struct {
		Tree   string `json:"tree"`
		Object string `json:"object"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parsing git predicate: %w", err)
	}
	switch {
	case probe.Tree != "" && probe.Object == "":
		commit := &Commit{}
		if err := unmarshalStrict(data, commit); err != nil {
			return nil, err
		}
		return &generic.Predicate{Type: PredicateTypeCommit, Parsed: commit, Data: data}, nil
	case probe.Object != "" && probe.Tree == "":
		tag := &Tag{}
		if err := unmarshalStrict(data, tag); err != nil {
			return nil, err
		}
		return &generic.Predicate{Type: PredicateTypeTag, Parsed: tag, Data: data}, nil
	default:
		return nil, attestation.ErrNotCorrectFormat
	}
}

// unmarshalStrict decodes data into v, refusing unknown fields: data with
// extra keys is another type that happens to share a field name.
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			return fmt.Errorf("parsing git predicate: %w", err)
		}
		return fmt.Errorf("%w: %w", attestation.ErrNotCorrectFormat, err)
	}
	return nil
}
