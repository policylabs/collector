// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package gitobject

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	sapi "github.com/policylabs/signer/api/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	rekortypes "github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// oidRekorTransparencyLogEntry is the OID under which gitsign embeds a serialized
// Rekor TransparencyLogEntry proto in the CMS unsigned attributes when signing in
// offline mode (see gitsign internal/rekor/oid). Its presence is what distinguishes
// an offline-verifiable object from an online-mode one.
var oidRekorTransparencyLogEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}

// DefaultRekorURL is the sigstore public-good transparency log, queried for
// the online-mode Rekor lookup when a signature carries no embedded entry.
const DefaultRekorURL = "https://rekor.sigstore.dev"

// verifySigstoreSignature performs full, cosign-free cryptographic verification of
// a gitsign CMS/PKCS7 signature. It handles both gitsign signing modes:
//   - Offline mode: the signature embeds the Rekor transparency log entry, verified
//     entirely against the embedded trust root with zero network.
//   - Online mode: the signature carries no embedded entry, so the entry is looked
//     up in Rekor and then verified through the exact same offline path. The network
//     is used only to fetch the entry; its inclusion proof and SET are still checked
//     against the embedded trust root. A lookup that finds nothing, errors, or yields
//     no matching entry fails closed (nil, error).
//
// When it returns a non-nil Verification with Verified:true, ALL of the following
// held, using only the embedded trust root for the cryptographic checks:
//  1. The CMS signature covers signedData and the leaf chains to a Fulcio CA.
//  2. The Rekor entry is included in the transparency log (inclusion proof + SET),
//     which also fixes the integrated (signing) time.
//  3. The leaf certificate was valid at signing time and carries a valid SCT.
func (v *Verifier) verifySigstoreSignature(ctx context.Context, signedData, cmsRaw, legacyArtifact []byte) (*sapi.Verification, error) {
	// Parse the CMS with the protocol package to reach the raw SignerInfo (its
	// signature, signed attributes and the unsigned Rekor-entry attribute).
	ci, err := protocol.ParseContentInfo(cmsRaw)
	if err != nil {
		return nil, fmt.Errorf("parsing CMS content info: %w", err)
	}
	psd, err := ci.SignedDataContent()
	if err != nil {
		return nil, fmt.Errorf("getting signed data: %w", err)
	}
	if len(psd.SignerInfos) == 0 {
		return nil, errors.New("no signer info in CMS signature")
	}
	si := psd.SignerInfos[0]

	certs, err := psd.X509Certificates()
	if err != nil {
		return nil, fmt.Errorf("extracting certificates: %w", err)
	}
	leaf, err := si.FindCertificate(certs)
	if err != nil {
		return nil, fmt.Errorf("finding signer certificate: %w", err)
	}

	trustedRoot, err := v.trusted()
	if err != nil {
		return nil, fmt.Errorf("loading trust root: %w", err)
	}

	// Step 1: the CMS signature cryptographically covers signedData (via the
	// messageDigest signed attribute) and the leaf chains to Fulcio.
	if err := verifyCMSSignature(signedData, cmsRaw, leaf, trustedRoot); err != nil {
		return nil, fmt.Errorf("verifying CMS signature: %w", err)
	}

	// The Rekor hashedrekord records the SHA-256 of the DER-encoded CMS signed
	// attributes (exactly what gitsign hashes), signed by si.Signature. Recompute
	// that digest so the synthetic bundle matches what was logged.
	signedAttrs, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, fmt.Errorf("marshaling CMS signed attributes: %w", err)
	}
	digest := sha256.Sum256(signedAttrs)

	// Obtain the Rekor TransparencyLogEntry and verify it through the shared
	// offline path. There are three cases:
	//
	//   - Offline signing: the entry is embedded in the CMS. It records the
	//     modern hashedrekord over the CMS signed attributes, so verify it with
	//     si.Signature and the signed-attrs digest.
	//   - Online, modern scheme: no embedded entry; look it up in Rekor by the
	//     signed-attrs digest and verify it the same way.
	//   - Online, legacy scheme: gitsign's default online mode (git.LegacySHASign)
	//     and every older commit/tag instead log a hashedrekord over the object's
	//     own git hash, signed separately by the ephemeral key. When the modern
	//     lookup finds nothing, fall back to that: look the entry up by
	//     sha256(<object git hash>) and verify it with the entry's own signature.
	entryProto, ok, err := extractTlogEntry(&si)
	if err != nil {
		return nil, fmt.Errorf("extracting embedded transparency log entry: %w", err)
	}
	if ok {
		return v.verifyEntry(ctx, leaf, si.Signature, digest[:], entryProto, trustedRoot)
	}

	logrus.Debug("gitobject: signature has no embedded Rekor entry; looking it up online")
	if entryProto, err = v.lookupTlogEntry(ctx, leaf, si.Signature, digest[:]); err == nil {
		return v.verifyEntry(ctx, leaf, si.Signature, digest[:], entryProto, trustedRoot)
	}
	modernErr := err

	logrus.Debug("gitobject: no modern Rekor entry; trying the legacy (gitsign online) scheme")
	legacyEntry, legacySig, legacyDigest, legacyErr := v.lookupLegacyTlogEntry(ctx, leaf, legacyArtifact)
	if legacyErr != nil {
		return nil, fmt.Errorf("looking up transparency log entry (modern: %s; legacy: %w)", modernErr.Error(), legacyErr)
	}
	return v.verifyEntry(ctx, leaf, legacySig, legacyDigest, legacyEntry, trustedRoot)
}

// verifyEntry runs the shared verification path for a Rekor TransparencyLogEntry,
// regardless of whether it came from the embedded CMS attribute (offline mode) or a
// Rekor lookup (online mode). It rebuilds the hashedrekord bundle from the signature
// pieces, verifies transparency-log inclusion, then the leaf certificate validity and
// SCT — all against the embedded trust root with no network access — and finally
// summarizes the authenticated identity.
func (v *Verifier) verifyEntry(ctx context.Context, leaf *x509.Certificate, signature, digest []byte, entryProto *rekorpb.TransparencyLogEntry, trustedRoot *root.TrustedRoot) (*sapi.Verification, error) {
	entity, err := buildTlogBundle(ctx, leaf, signature, digest, entryProto)
	if err != nil {
		return nil, fmt.Errorf("assembling verification bundle: %w", err)
	}

	// Step 2: transparency-log inclusion (offline). This also cross-checks the entry
	// against the bundle (signature, key and hashedrekord digest) and yields the
	// trusted integrated (signing) time from the inclusion promise / SET.
	timestamps, err := sgverify.VerifyTlogEntry(entity, trustedRoot, 1, true)
	if err != nil {
		return nil, fmt.Errorf("verifying transparency log entry: %w", err)
	}
	if len(timestamps) == 0 {
		return nil, errors.New("transparency log entry produced no trusted timestamp")
	}
	integratedTime := timestamps[0].Time

	// Step 3: leaf certificate validity at signing time + SCT.
	chains, err := sgverify.VerifyLeafCertificate(integratedTime, leaf, trustedRoot)
	if err != nil {
		return nil, fmt.Errorf("verifying leaf certificate: %w", err)
	}
	if err := sgverify.VerifySignedCertificateTimestamp(chains, 1, trustedRoot); err != nil {
		return nil, fmt.Errorf("verifying signed certificate timestamp: %w", err)
	}

	// Identity: the collector reports authenticated identity only; allowlist
	// matching is the caller's (AMPEL's) responsibility.
	summary, err := certificate.SummarizeCertificate(leaf)
	if err != nil {
		return nil, fmt.Errorf("summarizing certificate: %w", err)
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:     timestamppb.Now(),
			Verified: true,
			Identities: []*sapi.Identity{
				{
					Sigstore: &sapi.IdentitySigstore{
						Issuer:   summary.Issuer,
						Identity: summary.SubjectAlternativeName,
					},
				},
			},
		},
	}, nil
}

// lookupTlogEntry performs the online-mode Rekor lookup: it reconstructs the exact
// hashedrekord body that gitsign would have logged for this signature, searches the
// transparency log by the artifact digest to obtain candidate entry UUIDs, fetches
// each candidate (with its inclusion proof and SET), and returns the one whose
// canonical body byte-matches ours converted to a TransparencyLogEntry proto. Byte
// equality is the honest match criterion: it is exactly what the inclusion proof
// commits to, so a non-matching entry could not pass the subsequent VerifyTlogEntry.
// It fails closed if the lookup errors or no candidate matches.
func (v *Verifier) lookupTlogEntry(ctx context.Context, leaf *x509.Certificate, signature, digest []byte) (*rekorpb.TransparencyLogEntry, error) {
	ourBody, err := canonicalHashedRekordBody(ctx, leaf, signature, digest)
	if err != nil {
		return nil, fmt.Errorf("reconstructing hashedrekord body: %w", err)
	}

	rekorURL := v.rekorURL
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	client, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("creating rekor client: %w", err)
	}

	// Search the log index by the artifact digest (the hashedrekord data.hash).
	searchParams := index.NewSearchIndexParams().
		WithQuery(&models.SearchIndex{Hash: "sha256:" + hex.EncodeToString(digest)})
	searchResp, err := client.Index.SearchIndexContext(ctx, searchParams)
	if err != nil {
		return nil, fmt.Errorf("searching rekor index: %w", err)
	}
	uuids := searchResp.GetPayload()
	if len(uuids) == 0 {
		return nil, errors.New("no rekor entry found for signature")
	}

	for _, uuid := range uuids {
		getParams := entries.NewGetLogEntryByUUIDParams().
			WithEntryUUID(uuid)
		entryResp, err := client.Entries.GetLogEntryByUUIDContext(ctx, getParams)
		if err != nil {
			logrus.Debugf("gitobject: fetching rekor entry %s: %v", uuid, err)
			continue
		}
		for _, anon := range entryResp.GetPayload() {
			body, ok := decodeEntryBody(anon)
			if !ok || !bytes.Equal(body, ourBody) {
				continue
			}
			tle, err := logEntryToProto(&anon, body)
			if err != nil {
				return nil, fmt.Errorf("converting rekor entry: %w", err)
			}
			return tle, nil
		}
	}
	return nil, errors.New("no matching rekor entry for signature")
}

// lookupLegacyTlogEntry performs the legacy-mode Rekor lookup for gitsign
// signatures produced by git.LegacySHASign — gitsign's default online mode, and
// what every older commit and tag used. Those do not log the CMS signed
// attributes; they log a hashedrekord whose artifact is the object's own git
// hash string (sha256 of the 40-character SHA-1 hex), signed separately by the
// ephemeral key. It searches Rekor for that digest and returns the first entry
// whose logged certificate is the signing leaf, along with the entry's own
// signature and digest, so verifyEntry can rebuild and verify the exact logged
// body. It fails closed if the lookup errors or no candidate matches.
func (v *Verifier) lookupLegacyTlogEntry(ctx context.Context, leaf *x509.Certificate, artifact []byte) (entry *rekorpb.TransparencyLogEntry, signature, digest []byte, err error) {
	if len(artifact) == 0 {
		return nil, nil, nil, errors.New("no artifact for legacy lookup")
	}
	artifactDigest := sha256.Sum256(artifact)

	rekorURL := v.rekorURL
	if rekorURL == "" {
		rekorURL = DefaultRekorURL
	}
	client, err := rekorclient.GetRekorClient(rekorURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("creating rekor client: %w", err)
	}

	searchParams := index.NewSearchIndexParams().
		WithQuery(&models.SearchIndex{Hash: "sha256:" + hex.EncodeToString(artifactDigest[:])})
	searchResp, err := client.Index.SearchIndexContext(ctx, searchParams)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("searching rekor index: %w", err)
	}
	uuids := searchResp.GetPayload()
	if len(uuids) == 0 {
		return nil, nil, nil, errors.New("no legacy rekor entry found for signature")
	}

	for _, uuid := range uuids {
		getParams := entries.NewGetLogEntryByUUIDParams().
			WithEntryUUID(uuid)
		entryResp, err := client.Entries.GetLogEntryByUUIDContext(ctx, getParams)
		if err != nil {
			logrus.Debugf("gitobject: fetching legacy rekor entry %s: %v", uuid, err)
			continue
		}
		for _, anon := range entryResp.GetPayload() {
			body, ok := decodeEntryBody(anon)
			if !ok {
				continue
			}
			sig, ok := legacyHashedRekordSignature(body, leaf, artifactDigest[:])
			if !ok {
				continue
			}
			tle, err := logEntryToProto(&anon, body)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("converting legacy rekor entry: %w", err)
			}
			return tle, sig, artifactDigest[:], nil
		}
	}
	return nil, nil, nil, errors.New("no matching legacy rekor entry for signature")
}

// legacyHashedRekordSignature parses a fetched hashedrekord body and, when its
// data hash equals digest and its logged public key is the signing certificate,
// returns the entry's own signature. The certificate binding ties the Rekor
// entry to the same leaf that signed the object; the digest binding ties it to
// this object. It reports whether the entry corresponds to this signature.
func legacyHashedRekordSignature(body []byte, leaf *x509.Certificate, digest []byte) ([]byte, bool) {
	var hr struct {
		Spec struct {
			Data struct {
				Hash struct {
					Value string `json:"value"`
				} `json:"hash"`
			} `json:"data"`
			Signature struct {
				Content   string `json:"content"`
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &hr); err != nil {
		return nil, false
	}
	if hr.Spec.Data.Hash.Value != hex.EncodeToString(digest) {
		return nil, false
	}
	sig, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.Content)
	if err != nil {
		return nil, false
	}
	pubPEM, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, false
	}
	pubCerts, err := cryptoutils.UnmarshalCertificatesFromPEM(pubPEM)
	if err != nil || len(pubCerts) == 0 {
		return nil, false
	}
	if !pubCerts[0].Equal(leaf) {
		return nil, false
	}
	return sig, true
}

// decodeEntryBody base64-decodes the canonical body carried by a fetched Rekor entry.
func decodeEntryBody(anon models.LogEntryAnon) ([]byte, bool) {
	s, ok := anon.Body.(string)
	if !ok {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// logEntryToProto converts a Rekor models.LogEntryAnon (as returned by
// GetLogEntryByUUID, with its inclusion proof and SET) into the *rekorpb.
// TransparencyLogEntry that VerifyTlogEntry consumes offline. It is hand-rolled
// rather than using sigstore-go's tlog.NewEntry because NewEntry reuses the entry's
// global log index for the inclusion proof's log index; those differ on a sharded log
// (as in the gitsign fixture: entry index 22784639 vs proof leaf index 18621208),
// which would break inclusion verification. Here the two indices are kept distinct.
func logEntryToProto(anon *models.LogEntryAnon, body []byte) (*rekorpb.TransparencyLogEntry, error) {
	if anon.LogID == nil || anon.LogIndex == nil || anon.IntegratedTime == nil {
		return nil, errors.New("rekor log entry missing required fields")
	}
	if anon.Verification == nil {
		return nil, errors.New("rekor log entry missing verification material")
	}
	set := []byte(anon.Verification.SignedEntryTimestamp)
	if len(set) == 0 {
		return nil, errors.New("rekor log entry missing signed entry timestamp")
	}
	ip := anon.Verification.InclusionProof
	if ip == nil || ip.LogIndex == nil || ip.RootHash == nil || ip.TreeSize == nil || ip.Checkpoint == nil {
		return nil, errors.New("rekor log entry missing inclusion proof")
	}

	logID, err := hex.DecodeString(*anon.LogID)
	if err != nil {
		return nil, fmt.Errorf("decoding rekor log ID: %w", err)
	}
	rootHash, err := hex.DecodeString(*ip.RootHash)
	if err != nil {
		return nil, fmt.Errorf("decoding inclusion proof root hash: %w", err)
	}
	hashes := make([][]byte, len(ip.Hashes))
	for i, h := range ip.Hashes {
		hashes[i], err = hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("decoding inclusion proof hash: %w", err)
		}
	}

	return &rekorpb.TransparencyLogEntry{
		LogIndex: *anon.LogIndex,
		LogId:    &protocommon.LogId{KeyId: logID},
		KindVersion: &rekorpb.KindVersion{
			Kind:    hashedrekord.KIND,
			Version: hashedrekord_v001.APIVERSION,
		},
		IntegratedTime:   *anon.IntegratedTime,
		InclusionPromise: &rekorpb.InclusionPromise{SignedEntryTimestamp: set},
		InclusionProof: &rekorpb.InclusionProof{
			LogIndex:   *ip.LogIndex,
			RootHash:   rootHash,
			TreeSize:   *ip.TreeSize,
			Hashes:     hashes,
			Checkpoint: &rekorpb.Checkpoint{Envelope: *ip.Checkpoint},
		},
		CanonicalizedBody: body,
	}, nil
}

// extractTlogEntry pulls the serialized Rekor TransparencyLogEntry proto out of the
// CMS unsigned attributes (offline mode). It returns ok=false when the attribute is
// absent (online mode); a malformed attribute is an error.
func extractTlogEntry(si *protocol.SignerInfo) (*rekorpb.TransparencyLogEntry, bool, error) {
	if !si.UnsignedAttrs.HasAttribute(oidRekorTransparencyLogEntry) {
		return nil, false, nil
	}
	rv, err := si.UnsignedAttrs.GetOnlyAttributeValueBytes(oidRekorTransparencyLogEntry)
	if err != nil {
		return nil, false, fmt.Errorf("reading tlog attribute: %w", err)
	}
	var protoBytes []byte
	if _, err := asn1.Unmarshal(rv.FullBytes, &protoBytes); err != nil {
		return nil, false, fmt.Errorf("asn1-decoding tlog attribute: %w", err)
	}
	pb := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(protoBytes, pb); err != nil {
		return nil, false, fmt.Errorf("unmarshaling TransparencyLogEntry: %w", err)
	}
	return pb, true, nil
}

// verifyCMSSignature checks that the detached CMS signature covers signedData and
// that the signer certificate chains to a Fulcio CA in the trust root. It mirrors
// gitsign's own pkg/git.CertVerifier, including the "cosign hack" of pinning the
// verification time to the leaf's NotBefore (the transparency log establishes the
// real signing time separately).
func verifyCMSSignature(signedData, cmsRaw []byte, leaf *x509.Certificate, trustedRoot *root.TrustedRoot) error {
	sd, err := cms.ParseSignedData(cmsRaw)
	if err != nil {
		return fmt.Errorf("parsing CMS: %w", err)
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for _, ca := range trustedRoot.FulcioCertificateAuthorities() {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		if fca.Root != nil {
			roots.AddCert(fca.Root)
		}
		for _, intermediate := range fca.Intermediates {
			intermediates.AddCert(intermediate)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time and pin to the cert's validity
		// window; the tlog inclusion proof establishes the true signing time.
		CurrentTime: leaf.NotBefore.Add(1 * time.Minute),
	}
	if _, err := sd.VerifyDetached(signedData, opts); err != nil {
		return fmt.Errorf("verifying detached signature: %w", err)
	}
	return nil
}

// canonicalHashedRekordBody reconstructs the exact canonical Rekor hashedrekord body
// gitsign logs for a signature: data.hash = the given digest (SHA-256 of the CMS
// signed attributes), signature = si.Signature, public key = the leaf cert PEM. Both
// the offline bundle assembly and the online lookup rely on this being byte-identical
// to what Rekor stored. CanonicalizeEntry additionally verifies that the signature
// validates over the digest with the leaf's public key, so a body that does not
// correspond to the leaf + signature cannot be reconstructed.
func canonicalHashedRekordBody(ctx context.Context, leaf *x509.Certificate, signature, digest []byte) ([]byte, error) {
	certPEM, err := cryptoutils.MarshalCertificateToPEM(leaf)
	if err != nil {
		return nil, fmt.Errorf("marshaling certificate to PEM: %w", err)
	}

	rekorEntry := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer("sha256"),
					Value:     conv.Pointer(hex.EncodeToString(digest)),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := rekortypes.CanonicalizeEntry(ctx, rekorEntry)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing rekor entry: %w", err)
	}
	return body, nil
}

// buildTlogBundle synthesizes the sigstore-go SignedEntity that VerifyTlogEntry
// consumes. It clones the TransparencyLogEntry (embedded or looked up) and attaches
// the canonical hashedrekord body rebuilt from the signature pieces, matching gitsign
// internal/rekor/oid.ToLogEntry.
//
// The bundle's MessageSignature carries the SAME digest and signature that the
// hashedrekord records, so VerifyTlogEntry's equality checks (entry.Signature ==
// bundle signature, key match, hashedrekord digest == message digest) are satisfied
// honestly: rebuilding the body with any other digest/signature would fail the
// inclusion-proof/SET check, and a bundle digest that diverged from the entry would
// fail the explicit equality check.
func buildTlogBundle(ctx context.Context, leaf *x509.Certificate, signature, digest []byte, entryProto *rekorpb.TransparencyLogEntry) (*sgbundle.Bundle, error) {
	body, err := canonicalHashedRekordBody(ctx, leaf, signature, digest)
	if err != nil {
		return nil, err
	}

	entry, ok := proto.Clone(entryProto).(*rekorpb.TransparencyLogEntry)
	if !ok {
		return nil, errors.New("cloning transparency log entry")
	}
	entry.CanonicalizedBody = body

	// v0.1 bundles require an inclusion promise; v0.2+ require an inclusion proof.
	// Pick the media type that matches what the embedded entry actually carries.
	mediaType := "application/vnd.dev.sigstore.bundle.v0.1+json"
	if entry.GetInclusionProof() != nil {
		mediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"
	}

	pb := &protobundle.Bundle{
		MediaType: mediaType,
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: leaf.Raw},
			},
			TlogEntries: []*rekorpb.TransparencyLogEntry{entry},
		},
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest,
				},
				Signature: signature,
			},
		},
	}
	return sgbundle.NewBundle(pb)
}
