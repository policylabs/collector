// SPDX-FileCopyrightText: Copyright 2026 The Policy Labs Project Contributors
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
	"github.com/policylabs/collector/repository/coci"
	"github.com/policylabs/collector/repository/gitsign"
	"github.com/policylabs/collector/repository/pypi"
)

// keptOrigin parses data, keeps its content and returns the origin as it
// reads after travelling serialized.
func keptOrigin(t *testing.T, data []byte) (attestation.Envelope, *intoto.ResourceDescriptor) {
	t.Helper()
	envs, err := envelope.Parsers.Parse(bytes.NewReader(data))
	require.NoError(t, err)
	require.Len(t, envs, 1)
	envelope.KeepContent(envs, data)

	rd, ok := envs[0].GetPredicate().GetOrigin().(*intoto.ResourceDescriptor)
	require.True(t, ok)
	serialized, err := protojson.Marshal(rd)
	require.NoError(t, err)
	origin := &intoto.ResourceDescriptor{}
	require.NoError(t, protojson.Unmarshal(serialized, origin))
	return envs[0], origin
}

func TestEnvelopesFromOriginParses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		path string
	}{
		{"bundle", "envelope/bundle/testdata/bundle-provenance.json"},
		{"statement", "repository/filesystem/testdata/results.intoto.json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(tc.path)
			require.NoError(t, err)
			original, origin := keptOrigin(t, data)

			envs, err := EnvelopesFromOrigin(t.Context(), origin, repository.ReassembleOptions{})
			require.NoError(t, err)
			require.Len(t, envs, 1)
			require.Equal(t, original.GetPredicate().GetType(), envs[0].GetPredicate().GetType())
			require.JSONEq(t, string(original.GetPredicate().GetData()), string(envs[0].GetPredicate().GetData()))

			// The attestation keeps the origin it was read from
			require.Same(t, origin, envs[0].GetPredicate().GetOrigin())
		})
	}
}

// A predicate that was not an attestation reads back too: it was kept as the
// statement wrapped around it.
func TestEnvelopesFromOriginWrappedPredicate(t *testing.T) {
	t.Parallel()
	data := []byte(`{"some":"report"}`)
	_, origin := keptOrigin(t, data)

	envs, err := EnvelopesFromOrigin(t.Context(), origin, repository.ReassembleOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.JSONEq(t, string(data), string(envs[0].GetPredicate().GetData()))
}

func TestEnvelopesFromOriginReassembles(t *testing.T) {
	t.Parallel()
	const moniker = "test-reassembler"
	fake := &fakeEnvelope{}
	var got *intoto.ResourceDescriptor
	var gotKeys []key.PublicKeyProvider
	require.NoError(t, RegisterReassembler(moniker, func(_ context.Context, origin *intoto.ResourceDescriptor, opts repository.ReassembleOptions) ([]attestation.Envelope, error) {
		got = origin
		gotKeys = opts.Keys
		return []attestation.Envelope{fake}, nil
	}))
	t.Cleanup(func() { UnregisterReassembler(moniker) })
	require.ErrorIs(t, RegisterReassembler(moniker, nil), ErrTypeAlreadyRegistered)

	// Content of a type no parser reads goes to the repository type the
	// origin names.
	origin := &intoto.ResourceDescriptor{Content: []byte("material"), MediaType: "application/x-something"}
	require.NoError(t, repository.Annotate(origin, moniker, map[string]any{"key": "value"}))

	// The options reach the reassembler
	priv, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	keys := []key.PublicKeyProvider{pub}

	envs, err := EnvelopesFromOrigin(t.Context(), origin, repository.ReassembleOptions{Keys: keys})
	require.NoError(t, err)
	require.Equal(t, []attestation.Envelope{fake}, envs)
	require.Same(t, origin, got)
	require.Equal(t, keys, gotKeys)
	require.Equal(t, map[string]any{"key": "value"}, repository.Material(got))
}

func TestEnvelopesFromOriginErrors(t *testing.T) {
	t.Parallel()
	const moniker = "test-failing-reassembler"
	errFailed := errors.New("failed")
	require.NoError(t, RegisterReassembler(moniker, func(context.Context, *intoto.ResourceDescriptor, repository.ReassembleOptions) ([]attestation.Envelope, error) {
		return nil, errFailed
	}))
	t.Cleanup(func() { UnregisterReassembler(moniker) })

	annotated := func(m string) *intoto.ResourceDescriptor {
		origin := &intoto.ResourceDescriptor{Content: []byte("material")}
		require.NoError(t, repository.Annotate(origin, m, nil))
		return origin
	}

	for _, tc := range []struct {
		name   string
		origin *intoto.ResourceDescriptor
		err    error
	}{
		{"nil", nil, ErrNoContent},
		{"no-content", &intoto.ResourceDescriptor{MediaType: "application/vnd.in-toto+json"}, ErrNoContent},
		{"no-repository", &intoto.ResourceDescriptor{Content: []byte("material")}, ErrCannotReassemble},
		{"unknown-repository", annotated("nothing-registered"), ErrCannotReassemble},
		{"reassembler-fails", annotated(moniker), errFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := EnvelopesFromOrigin(t.Context(), tc.origin, repository.ReassembleOptions{})
			require.ErrorIs(t, err, tc.err)
		})
	}

	t.Run("unparseable-attestation", func(t *testing.T) {
		t.Parallel()
		_, err := EnvelopesFromOrigin(t.Context(), &intoto.ResourceDescriptor{
			Content: []byte("{ not json"), MediaType: "application/vnd.dsse.envelope.v1+json",
		}, repository.ReassembleOptions{})
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrCannotReassemble)
	})
}

// The default types register the reassemblers of the repositories that keep
// content only they read back.
func TestDefaultReassemblers(t *testing.T) {
	t.Parallel()
	require.NoError(t, LoadDefaultRepositoryTypes())

	// Each one is reached: content it cannot use fails in the reassembler,
	// not for want of one.
	for _, moniker := range []string{coci.TypeMoniker, gitsign.TypeMoniker, pypi.TypeMoniker} {
		origin := &intoto.ResourceDescriptor{Content: []byte("not what the repository kept")}
		require.NoError(t, repository.Annotate(origin, moniker, nil))
		_, err := EnvelopesFromOrigin(t.Context(), origin, repository.ReassembleOptions{})
		require.Error(t, err, moniker)
		require.NotErrorIs(t, err, ErrCannotReassemble, moniker)
	}
}

// fakeEnvelope is an envelope with nothing in it.
type fakeEnvelope struct{}

func (*fakeEnvelope) GetStatement() attestation.Statement       { return nil }
func (*fakeEnvelope) GetPredicate() attestation.Predicate       { return nil }
func (*fakeEnvelope) GetSignatures() []attestation.Signature    { return nil }
func (*fakeEnvelope) GetCertificate() attestation.Certificate   { return nil }
func (*fakeEnvelope) GetVerification() attestation.Verification { return nil }
func (*fakeEnvelope) Verify(...any) error                       { return nil }
