// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package dsse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/carabiner-dev/hasher"
	"github.com/policylabs/attestation"
	sdsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/statement"
)

// Parser for attestations wrapped in DSSE envelopes
type Parser struct{}

// ParseFile parses a file and returns all envelopes in it.
func (p *Parser) ParseStream(r io.Reader) ([]attestation.Envelope, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading attestation envelope data: %w", err)
	}

	// Parse the envelope to its protobuf representation
	dsseEnvelope := &sdsse.Envelope{}
	// Since the envelope is simple (just three fields) we discard all
	// unknown JSON and check for the envelope integrity after parsing.
	// This avoids string matching on the error.
	unmarshler := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}
	if err := unmarshler.Unmarshal(data, dsseEnvelope); err != nil {
		return nil, fmt.Errorf("unmarshalling data: %w", err)
	}

	// Assign the proto to our envelope wrapper, keeping the original
	// bytes: they carry what the proto cannot (the cert extension) and
	// transparency log lookups key on them.
	env := Envelope{
		Envelope: dsseEnvelope,
	}
	env.SetRaw(data)

	// Sidecar-decode the cert extension keyless signers attach to each
	// signature; both decoders keep the array order, so the
	// certificates stay index-aligned with the proto signatures.
	var ext struct {
		Signatures []struct {
			Cert string `json:"cert"`
		} `json:"signatures"`
	}
	certs := map[int][]byte{}
	if err := json.Unmarshal(data, &ext); err == nil && len(ext.Signatures) == len(dsseEnvelope.GetSignatures()) {
		for i, sig := range ext.Signatures {
			if sig.Cert != "" {
				certs[i] = []byte(sig.Cert)
			}
		}
	}

	// If there is no payload and no sig, then don't treat the envelope as DSSE
	if env.Payload == nil && len(env.Signatures) == 0 {
		return nil, attestation.ErrNotCorrectFormat
	}

	for i, s := range env.Envelope.GetSignatures() {
		env.Signatures = append(env.Signatures, &Signature{
			KeyID:       s.GetKeyid(),
			Signature:   s.GetSig(),
			Certificate: certs[i],
		})
	}

	// Parse the envelope payload
	s, err := statement.Parsers.Parse(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("error parsing the envelope payload: %w", err)
	}
	env.Statement = s

	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return nil, fmt.Errorf("error hashing envelope data: %w", err)
	}
	// Reigster the attestation digests in its source
	if env.GetPredicate() != nil {
		env.GetPredicate().SetOrigin(digests.ToResourceDescriptors()[0])
	}

	return []attestation.Envelope{&env}, nil
}

// FileExtensions returns the file extennsions this parser will look at.
func (p *Parser) FileExtensions() []string {
	return []string{"json", "intoto"}
}

// MediaType is the media type of a DSSE envelope.
const MediaType = "application/vnd.dsse.envelope.v1+json"

// ReadsMediaType reports if the parser reads data of a media type.
func (p *Parser) ReadsMediaType(mediaType string) bool {
	return mediaType == MediaType
}
