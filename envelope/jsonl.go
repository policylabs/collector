// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/jsonl"
	"github.com/policylabs/attestation"
)

var _ attestation.EnvelopeParser = (*JsonlParser)(nil)

// JsonlParser is a virtual parser that splits the jsonl files into the contained
// JSON structs and calls the configured envelope parsers for each instance.
type JsonlParser struct {
	// KeepContent keeps the data of each attestation in the content of its
	// origin (see KeepContent).
	KeepContent bool
}

func NewJSONL() *JsonlParser {
	return &JsonlParser{}
}

// TODO(puerco): We need a way to parse the data to detect if it's in linear json.
// Until then, we cannot add the parser to the parsers list.

// ParseFile parses a file and returns all envelopes in it.
func (jlp *JsonlParser) ParseStream(jsonlStream io.Reader) ([]attestation.Envelope, error) {
	ret := []attestation.Envelope{}
	for i, r := range jsonl.IterateBundle(jsonlStream) {
		if r == nil {
			continue
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("error reading struct #%d: %w", i, err)
		}
		att, err := Parsers.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("error parsing struct #%d: %w", i, err)
		}
		if jlp.KeepContent {
			KeepContent(att, data)
		}
		ret = append(ret, att...)
	}
	return ret, nil
}

// ParseFile takes a path and returns the attestations in the file
func (jlp *JsonlParser) ParseFile(path string) ([]attestation.Envelope, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	return jlp.ParseStream(f)
}

func (jlp *JsonlParser) Parse(data []byte) ([]attestation.Envelope, error) {
	return jlp.ParseStream(bytes.NewReader(data))
}

// FileExtensions returns the file extennsions this parser will look at.
func (jlp *JsonlParser) FileExtensions() []string {
	return []string{"jsonl"}
}
