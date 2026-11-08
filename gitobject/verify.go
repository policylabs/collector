// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitobject

import (
	"context"
	_ "embed"
	"encoding/pem"
	"fmt"
	"io"
	"sync"

	"github.com/go-git/go-git/v5/plumbing"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// githubWebFlowKey is GitHub's web-flow PGP key, the one GitHub signs with
// when it creates a commit itself: merges and squashes through the web and
// the API, and web edits. Fetched from https://github.com/web-flow.gpg; it
// holds the key GitHub rotated to in 2024 and the one before it.
//
//go:embed keys/github-web-flow.asc
var githubWebFlowKey []byte

var (
	builtinKeysOnce sync.Once
	builtinKeys     []key.PublicKeyProvider
	errBuiltinKeys  error
)

// BuiltinKeys returns the PGP keys the package ships with and always
// verifies against: GitHub's web-flow key.
func BuiltinKeys() ([]key.PublicKeyProvider, error) {
	builtinKeysOnce.Do(func() {
		pubs, err := key.ParseGPGPublicKey(githubWebFlowKey)
		if err != nil {
			errBuiltinKeys = fmt.Errorf("parsing the embedded GitHub key: %w", err)
			return
		}
		for _, p := range pubs {
			builtinKeys = append(builtinKeys, p)
		}
	})
	return builtinKeys, errBuiltinKeys
}

// Verifier checks the PGP signature of git objects against a key set.
type Verifier struct {
	mu   sync.RWMutex
	keys []key.PublicKeyProvider
}

// NewVerifier returns a Verifier that knows the built-in keys only.
func NewVerifier() *Verifier { return &Verifier{} }

// SetKeys replaces the configured keys; the built-in keys stay.
func (v *Verifier) SetKeys(keys []key.PublicKeyProvider) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = keys
}

// AddKeys adds to the configured keys.
func (v *Verifier) AddKeys(keys ...key.PublicKeyProvider) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys = append(v.keys, keys...)
}

// Keys returns the configured keys (without the built-in ones).
func (v *Verifier) Keys() []key.PublicKeyProvider {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys
}

// signedObject is a go-git commit or tag: it yields the bytes its
// signature was computed over.
type signedObject interface {
	EncodeWithoutSignature(plumbing.EncodedObject) error
}

// Verify checks an object's signature and returns the verification, or nil
// when the object is unsigned, carries a signature kind this verifier does
// not handle (sigstore CMS, SSH), or no key verifies it. A nil result means
// "nothing established", never "forged": the policy decides what an
// unverified object is worth.
func (v *Verifier) Verify(_ context.Context, obj signedObject, signature string) *sapi.Verification {
	if signature == "" {
		return nil
	}
	if block, _ := pem.Decode([]byte(signature)); block != nil && block.Type != "PGP SIGNATURE" {
		// "SIGNED MESSAGE" is a sigstore CMS signature (gitsign's, the gitsign
		// driver's to verify); "SSH SIGNATURE" is not handled.
		logrus.Debugf("gitobject: %s signature not verified here", block.Type)
		return nil
	}
	signed, err := encodeWithoutSignature(obj)
	if err != nil {
		logrus.Debugf("gitobject: encoding object without signature: %v", err)
		return nil
	}
	builtin, err := BuiltinKeys()
	if err != nil {
		logrus.Debugf("gitobject: %v", err)
	}
	verifier := key.NewVerifier()
	var identities []*sapi.Identity
	for _, pkp := range append(v.Keys(), builtin...) {
		// A private key verifies through its public half: the signer takes
		// the OpenPGP path only for a *GPGPublic.
		if priv, ok := pkp.(*key.GPGPrivate); ok {
			pkp = priv.GPGPublicKey()
		}
		verified, err := verifier.VerifyMessage(pkp, signed, []byte(signature))
		if err != nil || !verified {
			continue
		}
		pub, err := pkp.PublicKey()
		if err != nil {
			continue
		}
		identities = append(identities, &sapi.Identity{
			Key: &sapi.IdentityKey{Id: pub.ID(), Type: string(pub.Scheme), Data: pub.Data},
		})
	}
	if len(identities) == 0 {
		return nil
	}
	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   true,
			Identities: identities,
		},
	}
}

// encodeWithoutSignature returns the canonical bytes a detached signature
// covers: the object serialized without its signature header.
func encodeWithoutSignature(obj signedObject) ([]byte, error) {
	enc := &plumbing.MemoryObject{}
	if err := obj.EncodeWithoutSignature(enc); err != nil {
		return nil, fmt.Errorf("encoding object without signature: %w", err)
	}
	reader, err := enc.Reader()
	if err != nil {
		return nil, fmt.Errorf("reading encoded object: %w", err)
	}
	return io.ReadAll(reader)
}
