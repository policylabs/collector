// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
)

var (
	reassemblers = map[string]repository.Reassembler{}

	// ErrNoContent is returned when an origin keeps no content to read.
	ErrNoContent = errors.New("origin keeps no content")

	// ErrCannotReassemble is returned when the content of an origin is not
	// an attestation and nothing is registered to rebuild one from it.
	ErrCannotReassemble = errors.New("content is not an attestation and cannot be reassembled into one")
)

// RegisterReassembler registers the function that rebuilds the attestations
// of a repository type from the content it keeps in their origin. A moniker
// that already has one keeps it, and the call answers
// ErrTypeAlreadyRegistered.
func RegisterReassembler(moniker string, fn repository.Reassembler) error {
	mtx.Lock()
	defer mtx.Unlock()
	if _, ok := reassemblers[moniker]; ok {
		return ErrTypeAlreadyRegistered
	}
	reassemblers[moniker] = fn
	return nil
}

// UnregisterReassembler removes the reassembler of a repository type.
func UnregisterReassembler(moniker string) {
	mtx.Lock()
	delete(reassemblers, moniker)
	mtx.Unlock()
}

// EnvelopesFromOrigin reads back the attestations kept in an origin, as a
// repository returned them when it was asked to keep their content (see the
// KeepContent fetch option). They come back as read: not verified, and with
// the origin they were read from as their own.
//
// Content of a media type an envelope parser reads is the attestation
// itself and is parsed. Any other content is what an attestation was built
// from: the origin names the repository type that kept it, and the
// reassembler registered for that type builds the attestation again.
func EnvelopesFromOrigin(ctx context.Context, origin *intoto.ResourceDescriptor) ([]attestation.Envelope, error) {
	if len(origin.GetContent()) == 0 {
		return nil, ErrNoContent
	}

	var envs []attestation.Envelope
	if parser := envelope.Parsers.ForMediaType(origin.GetMediaType()); parser != nil {
		var err error
		envs, err = parser.ParseStream(bytes.NewReader(origin.GetContent()))
		if err != nil {
			return nil, fmt.Errorf("parsing content of type %q: %w", origin.GetMediaType(), err)
		}
	} else {
		moniker := repository.Annotated(origin)
		if moniker == "" {
			return nil, fmt.Errorf("%w: the origin names no repository type", ErrCannotReassemble)
		}
		mtx.RLock()
		reassemble, ok := reassemblers[moniker]
		mtx.RUnlock()
		if !ok {
			return nil, fmt.Errorf("%w: no reassembler for repository type %q", ErrCannotReassemble, moniker)
		}
		var err error
		envs, err = reassemble(ctx, origin)
		if err != nil {
			return nil, fmt.Errorf("reassembling with repository type %q: %w", moniker, err)
		}
	}

	// The parsers record an origin of their own, the digest of what they
	// read. Give the attestations the one they were read from, which also
	// says where they came from and keeps their content.
	for _, env := range envs {
		if env != nil && env.GetPredicate() != nil {
			env.GetPredicate().SetOrigin(origin)
		}
	}
	return envs, nil
}
