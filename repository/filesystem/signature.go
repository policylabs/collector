// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package filesystem

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/carabiner-dev/hasher"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/policylabs/signer/options"
	sigstore "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/internal/verifier"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/statement/intoto"
)

// SignaturePredicateType is the predicate type for virtual signature attestations.
const SignaturePredicateType = attestation.PredicateType("https://carabiner.dev/ampel/signature/v1")

// defaultSignatureExtensions lists recognized raw signature file extensions.
var defaultSignatureExtensions = []string{".sig", ".gpg", ".asc"}

// defaultSigstoreBundleExtensions lists recognized sigstore bundle extensions.
var defaultSigstoreBundleExtensions = []string{".sigstore.json", ".bundle"}

// defaultCertificateExtensions lists recognized certificate file extensions.
// A certificate found alongside a raw signature (e.g. `<artifact>.sig` +
// `<artifact>.pem`) marks a cosign-style keyless detached signature.
var defaultCertificateExtensions = []string{".pem", ".crt", ".cert"}

// sigstoreHashAlgNames maps sigstore hash algorithm enum values to in-toto
// digest names used by the hasher package.
var sigstoreHashAlgNames = map[protocommon.HashAlgorithm]string{
	protocommon.HashAlgorithm_SHA2_256: "sha256",
	protocommon.HashAlgorithm_SHA2_384: "sha384",
	protocommon.HashAlgorithm_SHA2_512: "sha512",
}

// sigstoreHashToIntoto converts a sigstore HashAlgorithm to the in-toto
// digest name. Returns the lowercased string representation as fallback.
func sigstoreHashToIntoto(alg protocommon.HashAlgorithm) string {
	if name, ok := sigstoreHashAlgNames[alg]; ok {
		return name
	}
	return strings.ToLower(alg.String())
}

// getSignatureExtension returns the matching signature extension suffix
// for a path, or empty string if none matches. Checks longest suffixes
// first to handle multi-part extensions correctly.
func getSignatureExtension(path string, extensions []string) string {
	for _, ext := range extensions {
		if strings.HasSuffix(path, ext) {
			return ext
		}
	}
	return ""
}

// hasSignatureExtension returns true if the file has a recognized signature
// or sigstore bundle extension. These files are deferred to
// processSignaturePairs and skipped from inline attestation parsing
// during the walk.
func (c *Collector) hasSignatureExtension(path string) bool {
	return getSignatureExtension(path, c.SignatureExtensions) != "" ||
		getSignatureExtension(path, c.SigstoreBundleExtensions) != "" ||
		getSignatureExtension(path, c.CertificateExtensions) != ""
}

// processSignaturePairs identifies signature pairs from the collected file
// list and processes them. Sigstore bundles are processed first (digest
// extracted from the bundle, no artifact read needed). Raw signature files
// require a companion artifact for hashing and key-based verification.
func (c *Collector) processSignaturePairs(ctx context.Context, allFiles []string, opts attestation.FetchOptions) []attestation.Envelope {
	// Build a set for O(1) lookup
	fileSet := make(map[string]struct{}, len(allFiles))
	for _, f := range allFiles {
		fileSet[f] = struct{}{}
	}

	var ret []attestation.Envelope

	for _, path := range allFiles {
		var envs []attestation.Envelope

		// Check sigstore bundle extensions first. Sigstore bundles carry
		// the artifact digest inside the messageSignature so there is no
		// need to read the companion artifact.
		if ext := getSignatureExtension(path, c.SigstoreBundleExtensions); ext != "" {
			envs = c.processSigstoreBundle(path, ext, opts)
		} else if ext := getSignatureExtension(path, c.SignatureExtensions); ext != "" {
			// Raw signature extensions require a companion artifact.
			envs = c.processRawSignature(ctx, path, ext, fileSet, opts)
		} else {
			continue
		}

		ret = append(ret, envs...)
	}

	return ret
}

// processSigstoreBundle handles files with sigstore bundle extensions.
// It extracts the subject digest directly from the bundle's messageSignature
// without reading or hashing the companion artifact.
func (c *Collector) processSigstoreBundle(path, ext string, opts attestation.FetchOptions) []attestation.Envelope {
	artifactPath := strings.TrimSuffix(path, ext)

	sigData, err := fs.ReadFile(c.FS, path)
	if err != nil {
		logrus.Debugf("reading sigstore bundle %s: %v", path, err)
		return nil
	}

	// Try to parse as a normal attestation (DSSE bundle)
	parsed, err := envelope.Parsers.Parse(bytes.NewReader(sigData))
	if err == nil && len(parsed) > 0 {
		if opts.KeepContent {
			envelope.KeepContent(parsed, sigData)
		}
		if opts.Query != nil {
			parsed = opts.Query.Run(parsed)
		}
		return parsed
	}

	// Parse as sigstore bundle proto
	var bundle sigstore.Bundle
	if err := protojson.Unmarshal(sigData, &bundle); err != nil {
		logrus.Debugf("parsing sigstore bundle %s: %v", path, err)
		return nil
	}

	// Verify the bundle
	verification, err := c.verifySigstoreBundle(&bundle)
	if err != nil {
		logrus.Debugf("verifying sigstore bundle %s: %v", path, err)
		return nil
	}

	// Build virtual attestation with digest from the bundle
	env, err := c.buildSigstoreVirtualAttestation(artifactPath, &bundle, verification)
	if err != nil {
		logrus.Debugf("building virtual attestation for %s: %v", path, err)
		return nil
	}

	envs := []attestation.Envelope{env}
	if opts.Query != nil {
		envs = opts.Query.Run(envs)
	}
	return envs
}

// processRawSignature handles files with raw signature extensions (.sig, .gpg, .asc).
// These require a companion artifact for key-based verification and hashing.
func (c *Collector) processRawSignature(ctx context.Context, path, ext string, fileSet map[string]struct{}, opts attestation.FetchOptions) []attestation.Envelope {
	artifactPath := strings.TrimSuffix(path, ext)
	if _, ok := fileSet[artifactPath]; !ok {
		return nil
	}

	sigData, err := fs.ReadFile(c.FS, path)
	if err != nil {
		logrus.Debugf("reading signature file %s: %v", path, err)
		return nil
	}

	// Try to parse as a normal attestation (DSSE/bundle)
	parsed, err := envelope.Parsers.Parse(bytes.NewReader(sigData))
	if err == nil && len(parsed) > 0 {
		if opts.KeepContent {
			envelope.KeepContent(parsed, sigData)
		}
		if opts.Query != nil {
			parsed = opts.Query.Run(parsed)
		}
		return parsed
	}

	// A certificate companion (<artifact>.pem/.crt/.cert) alongside the
	// signature marks a cosign-style keyless detached signature. Verify it
	// against the Fulcio certificate and the Rekor transparency log instead
	// of against locally configured keys.
	if certPath, ok := c.certificateCompanion(artifactPath, fileSet); ok {
		return c.processCertSignaturePair(ctx, artifactPath, certPath, sigData, opts)
	}

	// Verify with configured keys (handles GPG, ECDSA, RSA, Ed25519)
	verification, err := c.verifyWithKeys(artifactPath, sigData)
	if err != nil {
		logrus.Debugf("verifying signature for %s: %v", artifactPath, err)
		return nil
	}

	env, err := c.buildVirtualAttestation(artifactPath, verification)
	if err != nil {
		logrus.Debugf("building virtual attestation for %s: %v", artifactPath, err)
		return nil
	}

	envs := []attestation.Envelope{env}
	if opts.Query != nil {
		envs = opts.Query.Run(envs)
	}
	return envs
}

// verifySigstoreBundle verifies a parsed sigstore bundle and extracts
// the signing identity from its certificate. It verifies with the verifier
// shared by the whole process: building one resolves the sigstore trusted
// roots (a TUF refresh over the network when the embedded ones have aged),
// which a directory or a release with many bundles must not pay per file.
func (c *Collector) verifySigstoreBundle(bundle *sigstore.Bundle) (*sapi.Verification, error) {
	if _, err := verifier.Default().VerifyParsedBundle(
		&sgbundle.Bundle{Bundle: bundle},
		options.WithSkipIdentityCheck(true),
	); err != nil {
		return nil, fmt.Errorf("verifying sigstore bundle: %w", err)
	}

	return c.extractSigstoreIdentity(bundle)
}

// extractSigstoreIdentity extracts the signing identity from the sigstore
// bundle's certificate.
func (c *Collector) extractSigstoreIdentity(bundle *sigstore.Bundle) (*sapi.Verification, error) {
	if bundle.GetVerificationMaterial() == nil {
		return nil, fmt.Errorf("no verification material in bundle")
	}

	var cert *protocommon.X509Certificate
	if c := bundle.GetVerificationMaterial().GetCertificate(); c != nil {
		cert = c
	}
	if chain := bundle.GetVerificationMaterial().GetX509CertificateChain(); cert == nil && chain != nil && len(chain.GetCertificates()) > 0 {
		cert = chain.GetCertificates()[0]
	}
	if cert == nil {
		return nil, fmt.Errorf("no certificate found in bundle")
	}

	x509cert, err := x509.ParseCertificate(cert.GetRawBytes())
	if err != nil {
		return nil, fmt.Errorf("parsing cert: %w", err)
	}

	summary, err := certificate.SummarizeCertificate(x509cert)
	if err != nil {
		return nil, fmt.Errorf("summarizing cert: %w", err)
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

// verifyWithKeys attempts to verify the raw signature against the artifact
// using the collector's configured keys.
func (c *Collector) verifyWithKeys(artifactPath string, sigData []byte) (*sapi.Verification, error) {
	if len(c.Keys) == 0 {
		return nil, fmt.Errorf("no keys configured for verification")
	}

	artifactContent, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("reading artifact: %w", err)
	}

	keyVerifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range c.Keys {
		verified, err := keyVerifier.VerifyMessage(pkp, artifactContent, sigData)
		if err != nil {
			logrus.Debugf("key verification error: %v", err)
			continue
		}
		if !verified {
			continue
		}

		pub, err := pkp.PublicKey()
		if err != nil {
			continue
		}

		identities = append(identities, &sapi.Identity{
			Key: &sapi.IdentityKey{
				Id:   pub.ID(),
				Type: string(pub.Scheme),
				Data: pub.Data,
			},
		})
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no key verified the signature")
	}

	return &sapi.Verification{
		Signature: &sapi.SignatureVerification{
			Date:       timestamppb.Now(),
			Verified:   true,
			Identities: identities,
		},
	}, nil
}

// buildSigstoreVirtualAttestation creates a virtual attestation for a verified
// sigstore bundle. The subject digest is extracted directly from the bundle's
// messageSignature, avoiding the need to read and hash the companion artifact.
func (c *Collector) buildSigstoreVirtualAttestation(artifactPath string, bundle *sigstore.Bundle, verification *sapi.Verification) (attestation.Envelope, error) {
	ms := bundle.GetMessageSignature()
	if ms == nil {
		return nil, fmt.Errorf("no message signature in bundle")
	}

	md := ms.GetMessageDigest()
	if md == nil {
		return nil, fmt.Errorf("no message digest in bundle")
	}

	algName := sigstoreHashToIntoto(md.GetAlgorithm())
	digestHex := fmt.Sprintf("%x", md.GetDigest())

	rd := &gointoto.ResourceDescriptor{
		Name: filepath.Base(artifactPath),
		Digest: map[string]string{
			algName: digestHex,
		},
	}

	pred := &generic.Predicate{
		Type:         SignaturePredicateType,
		Data:         []byte("{}"),
		Verification: verification,
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &virtualEnvelope{statement: stmt}, nil
}

// buildVirtualAttestation creates a virtual attestation envelope for a
// verified detached signature. It reads and hashes the artifact to form
// the subject.
func (c *Collector) buildVirtualAttestation(artifactPath string, verification *sapi.Verification) (attestation.Envelope, error) {
	artifactData, err := fs.ReadFile(c.FS, artifactPath)
	if err != nil {
		return nil, fmt.Errorf("reading artifact: %w", err)
	}

	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(artifactData)})
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}

	rds := hsets.ToResourceDescriptors()
	if len(rds) == 0 {
		return nil, fmt.Errorf("no hash computed for artifact")
	}

	rd := rds[0]
	rd.Name = filepath.Base(artifactPath)

	pred := &generic.Predicate{
		Type:         SignaturePredicateType,
		Data:         []byte("{}"),
		Verification: verification,
	}

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(rd),
	)

	return &virtualEnvelope{statement: stmt}, nil
}

// virtualEnvelope implements attestation.Envelope for virtual signature
// attestations. Unlike bare.Envelope, it delegates GetVerification
// through the statement chain.
type virtualEnvelope struct {
	statement attestation.Statement
}

var _ attestation.Envelope = (*virtualEnvelope)(nil)

func (e *virtualEnvelope) GetStatement() attestation.Statement {
	return e.statement
}

func (e *virtualEnvelope) GetPredicate() attestation.Predicate {
	if s := e.GetStatement(); s != nil {
		return s.GetPredicate()
	}
	return nil
}

func (e *virtualEnvelope) GetVerification() attestation.Verification {
	if s := e.GetStatement(); s != nil {
		return s.GetVerification()
	}
	return nil
}

func (e *virtualEnvelope) GetSignatures() []attestation.Signature {
	return nil
}

func (e *virtualEnvelope) GetCertificate() attestation.Certificate {
	return nil
}

func (e *virtualEnvelope) Verify(_ ...any) error {
	return nil
}
