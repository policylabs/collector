// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package repository

import (
	"context"
	"errors"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"google.golang.org/protobuf/types/known/structpb"
)

// Annotations a repository records in the origin of an attestation when the
// content it keeps there is not the attestation itself but what it was built
// from. An envelope parser cannot read such content back: the repository
// that kept it has to build the attestation again.
const (
	// AnnotationRepository names the repository type, by its moniker, that
	// reassembles the attestation from the content of the origin.
	AnnotationRepository = "github.com/policylabs/collector/repository"

	// AnnotationMaterial holds what the repository needs to reassemble the
	// attestation that is not in the content. Its shape is private to each
	// repository type.
	AnnotationMaterial = "github.com/policylabs/collector/material"
)

// Reassembler rebuilds the attestations a repository type made out of the
// content kept in an origin, from that content and the material recorded
// with it. It gives back what the repository returned when it first read
// them, not verified.
type Reassembler func(ctx context.Context, origin *intoto.ResourceDescriptor) ([]attestation.Envelope, error)

// Annotate records in an origin the repository type that reassembles its
// content and the material it needs to do it. Other annotations are kept.
func Annotate(origin *intoto.ResourceDescriptor, moniker string, material map[string]any) error {
	if origin == nil {
		return errors.New("no origin to annotate")
	}
	if moniker == "" {
		return errors.New("no repository type to annotate the origin with")
	}
	m, err := structpb.NewStruct(material)
	if err != nil {
		return fmt.Errorf("encoding reassembly material: %w", err)
	}
	if origin.GetAnnotations() == nil {
		origin.Annotations = &structpb.Struct{}
	}
	if origin.GetAnnotations().GetFields() == nil {
		origin.Annotations.Fields = map[string]*structpb.Value{}
	}
	origin.Annotations.Fields[AnnotationRepository] = structpb.NewStringValue(moniker)
	origin.Annotations.Fields[AnnotationMaterial] = structpb.NewStructValue(m)
	return nil
}

// Annotated returns the repository type an origin names to reassemble its
// content, empty when it names none.
func Annotated(origin *intoto.ResourceDescriptor) string {
	return origin.GetAnnotations().GetFields()[AnnotationRepository].GetStringValue()
}

// Material returns the reassembly material recorded in an origin as plain
// values, nil when there is none.
func Material(origin *intoto.ResourceDescriptor) map[string]any {
	m := origin.GetAnnotations().GetFields()[AnnotationMaterial].GetStructValue()
	if m == nil {
		return nil
	}
	return m.AsMap()
}
