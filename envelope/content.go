// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
)

// KeepContent records data, the bytes an envelope was parsed from, as the
// content of the origin of its predicate. Repositories call it when asked to
// through the KeepContent fetch option, so that a consumer can carry the
// evidence it evaluated along with its results.
//
// The content is only kept when data produced exactly one envelope and the
// parser recorded its origin as a resource descriptor: that is when the
// origin's digest is the digest of data. Anything else is left untouched.
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
