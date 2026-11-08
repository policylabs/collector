// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitobject

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	signersigstore "github.com/policylabs/signer/sigstore"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/stretchr/testify/require"
)

const rekorFixtureUUID = "24296fb24b8ad77a62b622b0ab5955d18e8ed89c257492bc0e56aec26b961aafe8f3c8931db4a9fd"

const offlineFixture = "testdata/offline.commit"

// legacyFixture is a commit signed with gitsign's default (legacy, online) mode:
// no embedded Rekor entry, and the entry logged over the commit's own git hash.
const legacyFixture = "testdata/legacy-online.commit"

const legacyFixtureUUID = "108e9186e8c5677aa6663e2cc8bdacabf92381f3c3a99ae2a6bbfbd71ef60db0c5aca25e37608fd4"

// loadOfflineCommit reads the raw git commit object fixture (as produced by
// `git cat-file commit <sha>`) into a go-git commit.
func loadOfflineCommit(t *testing.T) *object.Commit {
	t.Helper()
	raw, err := os.ReadFile(offlineFixture)
	require.NoError(t, err)

	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)

	commit, err := object.DecodeCommit(storage, obj)
	require.NoError(t, err)
	return commit
}

// loadLegacyCommit reads the legacy (online, no embedded entry) commit fixture
// into a go-git commit.
func loadLegacyCommit(t *testing.T) *object.Commit {
	t.Helper()
	raw, err := os.ReadFile(legacyFixture)
	require.NoError(t, err)

	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	require.NoError(t, err)
	_, err = w.Write(raw)
	require.NoError(t, err)

	commit, err := object.DecodeCommit(storage, obj)
	require.NoError(t, err)
	return commit
}

// fixtureCMS holds the decomposed CMS pieces of the offline fixture.
type fixtureCMS struct {
	commit *object.Commit
	si     protocol.SignerInfo
	leaf   *x509.Certificate
	cmsRaw []byte
	body   []byte
}

func loadFixtureCMS(t *testing.T) fixtureCMS {
	t.Helper()
	commit := loadOfflineCommit(t)

	block, _ := pem.Decode([]byte(commit.PGPSignature))
	require.NotNil(t, block)
	ci, err := protocol.ParseContentInfo(block.Bytes)
	require.NoError(t, err)
	psd, err := ci.SignedDataContent()
	require.NoError(t, err)
	require.NotEmpty(t, psd.SignerInfos)
	si := psd.SignerInfos[0]
	certs, err := psd.X509Certificates()
	require.NoError(t, err)
	leaf, err := si.FindCertificate(certs)
	require.NoError(t, err)
	body, err := encodeWithoutSignature(commit)
	require.NoError(t, err)

	return fixtureCMS{commit: commit, si: si, leaf: leaf, cmsRaw: block.Bytes, body: body}
}

// TestVerifyOfflineCommit_Positive verifies a real gitsign offline-signed commit
// (with an embedded Rekor entry) end to end and asserts the authenticated identity.
func TestVerifyOfflineCommit_Positive(t *testing.T) {
	commit := loadOfflineCommit(t)

	ver := NewVerifier()
	v := ver.Verify(context.Background(), commit, commit.PGPSignature)

	require.NotNil(t, v, "offline-signed commit must produce a verification")
	require.NotNil(t, v.GetSignature())
	require.True(t, v.GetSignature().GetVerified(), "signature must genuinely verify")

	ids := v.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	require.NotNil(t, ids[0].GetSigstore())
	require.Equal(t, "billy@chainguard.dev", ids[0].GetSigstore().GetIdentity())
	require.Equal(t, "https://accounts.google.com", ids[0].GetSigstore().GetIssuer())
}

// TestVerifyOfflineCommit_TamperedBody proves the signature is cryptographically
// bound to THIS commit: flipping one byte of the covered bytes must fail.
func TestVerifyOfflineCommit_TamperedBody(t *testing.T) {
	f := loadFixtureCMS(t)
	ver := NewVerifier()

	tampered := append([]byte(nil), f.body...)
	tampered[len(tampered)/2] ^= 0xff

	v, err := ver.verifySigstoreSignature(context.Background(), tampered, f.cmsRaw, nil)
	require.Error(t, err, "flipping a commit byte must fail verification")
	require.Nil(t, v)
}

// TestVerifyOfflineCommit_TamperedSignature proves the CMS signature is really
// checked: flipping a byte of si.Signature (and re-serializing) must fail.
func TestVerifyOfflineCommit_TamperedSignature(t *testing.T) {
	commit := loadOfflineCommit(t)
	ver := NewVerifier()

	block, _ := pem.Decode([]byte(commit.PGPSignature))
	require.NotNil(t, block)
	ci, err := protocol.ParseContentInfo(block.Bytes)
	require.NoError(t, err)
	psd, err := ci.SignedDataContent()
	require.NoError(t, err)

	psd.SignerInfos[0].Signature[5] ^= 0xff
	der, err := psd.ContentInfoDER()
	require.NoError(t, err)

	body, err := encodeWithoutSignature(commit)
	require.NoError(t, err)

	v, err := ver.verifySigstoreSignature(context.Background(), body, der, nil)
	require.Error(t, err, "a tampered signature must fail verification")
	require.Nil(t, v)
}

// stripEmbeddedEntry re-serializes the fixture's CMS signature without its unsigned
// attributes, producing an "online-mode" signature (no embedded Rekor entry) plus the
// bytes it covers. Verifying it requires looking the entry up in Rekor.
func stripEmbeddedEntry(t *testing.T, commit *object.Commit) (signedBody, der []byte) {
	t.Helper()
	block, _ := pem.Decode([]byte(commit.PGPSignature))
	require.NotNil(t, block)
	ci, err := protocol.ParseContentInfo(block.Bytes)
	require.NoError(t, err)
	psd, err := ci.SignedDataContent()
	require.NoError(t, err)

	psd.SignerInfos[0].UnsignedAttrs = nil
	der, err = psd.ContentInfoDER()
	require.NoError(t, err)

	signedBody, err = encodeWithoutSignature(commit)
	require.NoError(t, err)
	return signedBody, der
}

// fixtureDigest recomputes SHA-256 of the CMS signed attributes: the artifact digest
// the gitsign hashedrekord records.
func fixtureDigest(t *testing.T, f *fixtureCMS) []byte {
	t.Helper()
	signedAttrs, err := f.si.SignedAttrs.MarshaledForVerification()
	require.NoError(t, err)
	d := sha256.Sum256(signedAttrs)
	return d[:]
}

// loadRekorFixture reads the captured Rekor GetLogEntryByUUID response for the offline
// fixture's entry (log index 22784639) into a models.LogEntryAnon.
func loadRekorFixture(t *testing.T) *models.LogEntryAnon {
	t.Helper()
	raw, err := os.ReadFile("testdata/rekor-entry-22784639.json")
	require.NoError(t, err)
	var le models.LogEntry
	require.NoError(t, json.Unmarshal(raw, &le))
	require.Len(t, le, 1)
	for _, anon := range le {
		return &anon
	}
	return nil
}

// mockRekor stands up an httptest server that answers the two calls the online lookup
// makes: SearchIndex (returns the given UUIDs) and GetLogEntryByUUID (returns the raw
// LogEntry body). It lets the full online path run without touching the network.
func mockRekor(t *testing.T, uuids []string, entryBody []byte) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/index/retrieve", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(uuids); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	mux.HandleFunc("/api/v1/log/entries/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(entryBody); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestVerifyOnlineEntry_Converter proves the online converter + shared verify path:
// the captured Rekor entry is converted to a TransparencyLogEntry and fully verified
// offline against the embedded trust root (inclusion proof + SET), yielding the
// authenticated identity. It also asserts the two log indices are kept distinct (the
// entry's global index vs the inclusion proof's leaf index on a sharded log).
func TestVerifyOnlineEntry_Converter(t *testing.T) {
	f := loadFixtureCMS(t)
	digest := fixtureDigest(t, &f)

	anon := loadRekorFixture(t)
	body, ok := decodeEntryBody(*anon)
	require.True(t, ok)

	entryProto, err := logEntryToProto(anon, body)
	require.NoError(t, err)
	require.Equal(t, int64(22784639), entryProto.GetLogIndex())
	require.Equal(t, int64(18621208), entryProto.GetInclusionProof().GetLogIndex(),
		"inclusion proof leaf index must be preserved distinct from the global log index")
	require.NotEmpty(t, entryProto.GetInclusionPromise().GetSignedEntryTimestamp())

	ver := NewVerifier()
	tr, err := ver.trusted()
	require.NoError(t, err)

	v, err := ver.verifyEntry(context.Background(), f.leaf, f.si.Signature, digest, entryProto, tr)
	require.NoError(t, err)
	require.NotNil(t, v)
	require.True(t, v.GetSignature().GetVerified())
	require.Equal(t, "billy@chainguard.dev", v.GetSignature().GetIdentities()[0].GetSigstore().GetIdentity())
	require.Equal(t, "https://accounts.google.com", v.GetSignature().GetIdentities()[0].GetSigstore().GetIssuer())
}

// TestVerifyOnlineCommit_MockRekor drives the entire online path end to end against a
// mock Rekor: an online-mode signature (no embedded entry) is verified by looking the
// entry up, matching it, converting it, and verifying it — all offline.
func TestVerifyOnlineCommit_MockRekor(t *testing.T) {
	f := loadFixtureCMS(t)
	body, der := stripEmbeddedEntry(t, f.commit)

	raw, err := os.ReadFile("testdata/rekor-entry-22784639.json")
	require.NoError(t, err)

	url := mockRekor(t, []string{rekorFixtureUUID}, raw)
	ver := NewVerifier(WithRekorURL(url))

	v, err := ver.verifySigstoreSignature(context.Background(), body, der, []byte(f.commit.Hash.String()))
	require.NoError(t, err)
	require.NotNil(t, v, "online-mode commit must verify once the entry is fetched")
	require.True(t, v.GetSignature().GetVerified())
	require.Equal(t, "billy@chainguard.dev", v.GetSignature().GetIdentities()[0].GetSigstore().GetIdentity())
}

// TestLookupTlogEntry_NotFound proves the online lookup fails closed when Rekor
// returns no candidate entries.
func TestLookupTlogEntry_NotFound(t *testing.T) {
	f := loadFixtureCMS(t)
	digest := fixtureDigest(t, &f)

	url := mockRekor(t, []string{}, nil)
	ver := NewVerifier(WithRekorURL(url))

	entryProto, err := ver.lookupTlogEntry(context.Background(), f.leaf, f.si.Signature, digest)
	require.Error(t, err)
	require.Nil(t, entryProto)
}

// TestLookupTlogEntry_NoMatch proves that a fetched candidate whose body does not
// match our signature is not accepted (fail closed), even though the search returned
// a UUID. We serve a valid entry whose canonical body differs from ours.
func TestLookupTlogEntry_NoMatch(t *testing.T) {
	f := loadFixtureCMS(t)
	digest := fixtureDigest(t, &f)

	anon := loadRekorFixture(t)
	anon.Body = base64.StdEncoding.EncodeToString([]byte("not-our-canonical-body"))
	le := models.LogEntry{rekorFixtureUUID: *anon}
	raw, err := json.Marshal(le)
	require.NoError(t, err)

	url := mockRekor(t, []string{rekorFixtureUUID}, raw)
	ver := NewVerifier(WithRekorURL(url))

	entryProto, err := ver.lookupTlogEntry(context.Background(), f.leaf, f.si.Signature, digest)
	require.Error(t, err)
	require.Nil(t, entryProto)
}

// TestVerifyEntry_WrongDigest proves the network cannot make us trust a signature the
// fetched entry does not attest: verifying a genuine fetched entry against a different
// digest fails, because the bundle body is rebuilt from our own signature pieces.
func TestVerifyEntry_WrongDigest(t *testing.T) {
	f := loadFixtureCMS(t)

	anon := loadRekorFixture(t)
	body, ok := decodeEntryBody(*anon)
	require.True(t, ok)
	entryProto, err := logEntryToProto(anon, body)
	require.NoError(t, err)

	ver := NewVerifier()
	tr, err := ver.trusted()
	require.NoError(t, err)

	wrongDigest := make([]byte, sha256.Size) // all zeros: not what the signature covers
	v, err := ver.verifyEntry(context.Background(), f.leaf, f.si.Signature, wrongDigest, entryProto, tr)
	require.Error(t, err)
	require.Nil(t, v)
}

// TestLogEntryToProto_Guards proves the converter rejects incomplete Rekor entries.
func TestLogEntryToProto_Guards(t *testing.T) {
	base := loadRekorFixture(t)
	body, ok := decodeEntryBody(*base)
	require.True(t, ok)

	t.Run("no verification", func(t *testing.T) {
		anon := loadRekorFixture(t)
		anon.Verification = nil
		_, err := logEntryToProto(anon, body)
		require.Error(t, err)
	})
	t.Run("no inclusion proof", func(t *testing.T) {
		anon := loadRekorFixture(t)
		anon.Verification.InclusionProof = nil
		_, err := logEntryToProto(anon, body)
		require.Error(t, err)
	})
	t.Run("no SET", func(t *testing.T) {
		anon := loadRekorFixture(t)
		anon.Verification.SignedEntryTimestamp = nil
		_, err := logEntryToProto(anon, body)
		require.Error(t, err)
	})
}

// TestVerifyOnlineCommit_Live runs the full online path against the real Rekor public
// instance. It is skipped unless REKOR_ONLINE_TEST is set, so CI stays offline.
func TestVerifyOnlineCommit_Live(t *testing.T) {
	if os.Getenv("REKOR_ONLINE_TEST") == "" {
		t.Skip("set REKOR_ONLINE_TEST=1 to run the live Rekor integration test")
	}

	f := loadFixtureCMS(t)
	body, der := stripEmbeddedEntry(t, f.commit)

	ver := NewVerifier() // default: https://rekor.sigstore.dev
	v, err := ver.verifySigstoreSignature(context.Background(), body, der, []byte(f.commit.Hash.String()))
	require.NoError(t, err)
	require.NotNil(t, v)
	require.True(t, v.GetSignature().GetVerified())
	require.Equal(t, "billy@chainguard.dev", v.GetSignature().GetIdentities()[0].GetSigstore().GetIdentity())
}

// TestVerifyTlog_WrongRoot proves the transparency-log check is not vacuous: the
// exact same (honest) synthetic bundle fails to verify against a trust root that
// does not contain the Rekor log / Fulcio keys.
func TestVerifyTlog_WrongRoot(t *testing.T) {
	f := loadFixtureCMS(t)

	entryProto, ok, err := extractTlogEntry(&f.si)
	require.NoError(t, err)
	require.True(t, ok)

	signedAttrs, err := f.si.SignedAttrs.MarshaledForVerification()
	require.NoError(t, err)
	digest := sha256.Sum256(signedAttrs)

	entity, err := buildTlogBundle(context.Background(), f.leaf, f.si.Signature, digest[:], entryProto)
	require.NoError(t, err)

	// Sanity: it verifies against the real embedded root.
	good, err := signersigstore.TrustedRoot()
	require.NoError(t, err)
	_, err = sgverify.VerifyTlogEntry(entity, good, 1, true)
	require.NoError(t, err)

	// ...but not against an empty trust root.
	empty, err := root.NewTrustedRootFromJSON(
		[]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1"}`))
	require.NoError(t, err)
	_, err = sgverify.VerifyTlogEntry(entity, empty, 1, true)
	require.Error(t, err, "tlog entry must not verify without the Rekor log key")
}

// TestMessageDigestBindsCommit is the anti-vacuous unit check for the trap: the
// CMS messageDigest signed attribute equals SHA-256 of the commit bytes. This is
// the link that ties the CMS signature (and thus the whole tlog chain) to THIS
// commit's content.
func TestMessageDigestBindsCommit(t *testing.T) {
	f := loadFixtureCMS(t)

	messageDigest, err := f.si.GetMessageDigestAttribute()
	require.NoError(t, err)
	bodyDigest := sha256.Sum256(f.body)
	require.Equal(t, bodyDigest[:], messageDigest, "CMS messageDigest must equal SHA-256(commit body)")
}

// TestExtractTlogEntry checks OID extraction returns the embedded hashedrekord.
func TestExtractTlogEntry(t *testing.T) {
	f := loadFixtureCMS(t)

	entry, ok, err := extractTlogEntry(&f.si)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, entry)
	require.Equal(t, "hashedrekord", entry.GetKindVersion().GetKind())
	require.Positive(t, entry.GetLogIndex())
	// gitsign clears the canonical body; we must reconstruct it.
	require.Nil(t, entry.GetCanonicalizedBody())
}

// TestTrustedRootLoads confirms the embedded trust root parses and carries the
// Fulcio CAs and Rekor log keys needed for offline verification.
func TestTrustedRootLoads(t *testing.T) {
	tr, err := signersigstore.TrustedRoot()
	require.NoError(t, err)
	require.NotEmpty(t, tr.FulcioCertificateAuthorities())
	require.NotEmpty(t, tr.RekorLogs())
}

// TestVerifyLegacyOnlineCommit_MockRekor proves the legacy path end to end: a
// commit signed by gitsign's default git.LegacySHASign — no embedded entry, its
// Rekor entry logged over the commit's own git hash and signed separately — is
// verified by falling back from the modern lookup to the legacy lookup, matching
// the entry by sha256(<commit SHA>) and the signing certificate, then verifying
// it offline against the embedded trust root. The mock returns the legacy entry
// for both lookups; the modern lookup rejects it (body mismatch) and the legacy
// lookup accepts it.
func TestVerifyLegacyOnlineCommit_MockRekor(t *testing.T) {
	commit := loadLegacyCommit(t)
	block, _ := pem.Decode([]byte(commit.PGPSignature))
	require.NotNil(t, block)
	signedData, err := encodeWithoutSignature(commit)
	require.NoError(t, err)

	raw, err := os.ReadFile("testdata/rekor-entry-legacy.json")
	require.NoError(t, err)

	url := mockRekor(t, []string{legacyFixtureUUID}, raw)
	ver := NewVerifier(WithRekorURL(url))

	v, err := ver.verifySigstoreSignature(context.Background(), signedData, block.Bytes, []byte(commit.Hash.String()))
	require.NoError(t, err, "a legacy online-mode commit must verify via the legacy lookup")
	require.NotNil(t, v)
	require.True(t, v.GetSignature().GetVerified())
	require.Len(t, v.GetSignature().GetIdentities(), 1)
	require.Equal(t, "puerco@carabiner.dev",
		v.GetSignature().GetIdentities()[0].GetSigstore().GetIdentity())
	require.Equal(t, "https://accounts.google.com",
		v.GetSignature().GetIdentities()[0].GetSigstore().GetIssuer())
}

// TestLegacyHashedRekordSignature checks the legacy body parser in isolation: it
// returns the entry's signature only when the data hash matches sha256(<commit
// SHA>) AND the entry's logged certificate is the signing leaf.
func TestLegacyHashedRekordSignature(t *testing.T) {
	commit := loadLegacyCommit(t)
	block, _ := pem.Decode([]byte(commit.PGPSignature))
	require.NotNil(t, block)
	ci, err := protocol.ParseContentInfo(block.Bytes)
	require.NoError(t, err)
	psd, err := ci.SignedDataContent()
	require.NoError(t, err)
	certs, err := psd.X509Certificates()
	require.NoError(t, err)
	leaf, err := psd.SignerInfos[0].FindCertificate(certs)
	require.NoError(t, err)

	raw, err := os.ReadFile("testdata/rekor-entry-legacy.json")
	require.NoError(t, err)
	var le models.LogEntry
	require.NoError(t, json.Unmarshal(raw, &le))
	require.Len(t, le, 1)
	var anon models.LogEntryAnon
	for _, a := range le {
		anon = a
	}
	body, ok := decodeEntryBody(anon)
	require.True(t, ok)

	digest := sha256.Sum256([]byte(commit.Hash.String()))

	// Correct digest + correct leaf → returns the entry's signature.
	sig, ok := legacyHashedRekordSignature(body, leaf, digest[:])
	require.True(t, ok)
	require.NotEmpty(t, sig)

	// Wrong digest → no match.
	wrong := sha256.Sum256([]byte("not-the-commit"))
	_, ok = legacyHashedRekordSignature(body, leaf, wrong[:])
	require.False(t, ok, "a mismatched data hash must not match")

	// A different certificate → no match (the offline fixture's leaf is billy@).
	otherLeaf := loadFixtureCMS(t).leaf
	_, ok = legacyHashedRekordSignature(body, otherLeaf, digest[:])
	require.False(t, ok, "a different signing certificate must not match")
}
