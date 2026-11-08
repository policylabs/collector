// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitobject

import "github.com/policylabs/attestation"

// Envelope is the virtual envelope of a synthesized attestation: it carries
// a statement and no signature of its own. What vouches for the statement
// is the predicate's verification, the git object's signature.
type Envelope struct {
	statement attestation.Statement
}

var _ attestation.Envelope = (*Envelope)(nil)

// NewEnvelope wraps a statement.
func NewEnvelope(stmt attestation.Statement) *Envelope {
	return &Envelope{statement: stmt}
}

func (e *Envelope) GetStatement() attestation.Statement { return e.statement }

func (e *Envelope) GetPredicate() attestation.Predicate {
	if s := e.GetStatement(); s != nil {
		return s.GetPredicate()
	}
	return nil
}

func (e *Envelope) GetVerification() attestation.Verification {
	if s := e.GetStatement(); s != nil {
		return s.GetVerification()
	}
	return nil
}

func (*Envelope) GetSignatures() []attestation.Signature  { return nil }
func (*Envelope) GetCertificate() attestation.Certificate { return nil }
func (*Envelope) Verify(_ ...any) error                   { return nil }
