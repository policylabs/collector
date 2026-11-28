// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pypi

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/carabiner-dev/hasher"
	gointoto "github.com/in-toto/attestation/go/v1"
	gopurl "github.com/package-url/packageurl-go"
	"github.com/policylabs/attestation"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/repository"
	"github.com/policylabs/collector/statement/intoto"
)

// PublishPredicateType is the predicate type of the attestations PyPI's
// trusted publishing flow attaches to uploaded files. The specification
// defines its predicate as null: the attestation asserts nothing beyond the
// subject and the signer identity.
const PublishPredicateType = attestation.PredicateType("https://docs.pypi.org/attestations/publish/v1")

// ExtensionKey is the key under which the collector places the data it
// synthesizes into an otherwise empty publish predicate. The leading
// underscore marks it as a collector extension, not part of the PyPI
// specification, while keeping it a valid CEL identifier so policies can
// reach it as predicate._policylabs.
const ExtensionKey = "_policylabs"

// intotoPayloadType is the DSSE payload type of PEP 740 attestations.
const intotoPayloadType = "application/vnd.in-toto+json"

// Provenance is the PEP 740 provenance object served by the index for a
// distribution file. It groups the file's attestations by the trusted
// publisher that produced them.
type Provenance struct {
	Version            int                 `json:"version"`
	AttestationBundles []AttestationBundle `json:"attestation_bundles"`
}

// AttestationBundle is one publisher's attestations for a file. The
// publisher object is the index's description of the trusted publisher
// whose identity the attestations were verified against at upload time;
// its shape varies by publisher kind, so it is carried verbatim.
type AttestationBundle struct {
	Publisher    json.RawMessage `json:"publisher"`
	Attestations []Attestation   `json:"attestations"`
}

// Attestation is a single PEP 740 attestation: a DSSE-signed in-toto
// statement plus the sigstore material to verify it.
type Attestation struct {
	Version              int                  `json:"version"`
	VerificationMaterial VerificationMaterial `json:"verification_material"`
	Envelope             Envelope             `json:"envelope"`
}

// VerificationMaterial carries the signing certificate (base64 DER) and the
// transparency log entries, the latter in the sigstore protobuf JSON form.
type VerificationMaterial struct {
	Certificate         string            `json:"certificate"`
	TransparencyEntries []json.RawMessage `json:"transparency_entries"`
}

// Envelope is the flattened DSSE envelope of an attestation: the base64
// in-toto statement and the base64 signature over its PAE encoding.
type Envelope struct {
	Statement string `json:"statement"`
	Signature string `json:"signature"`
}

// Distribution identifies the distribution file a provenance object
// belongs to. The index addresses provenance by these three values.
type Distribution struct {
	// Project is the normalized project name.
	Project string `json:"project"`
	// Version is the release version.
	Version string `json:"version"`
	// Filename is the distribution file name (wheel or sdist).
	Filename string `json:"filename"`
	// PackageType is the index's file type (bdist_wheel, sdist) when known.
	PackageType string `json:"packageType,omitempty"`
	// URL is the file's download location when known.
	URL string `json:"url,omitempty"`
	// Index is the base URL of the index the provenance was read from.
	Index string `json:"index,omitempty"`
}

// purl returns the package URL of the distribution file.
func (d *Distribution) purl() string {
	return gopurl.NewPackageURL(
		gopurl.TypePyPi, "", d.Project, d.Version,
		gopurl.Qualifiers{{Key: fileNameQualifier, Value: d.Filename}}, "",
	).String()
}

// Extension is the data the collector synthesizes into a publish
// predicate, keyed under ExtensionKey. Everything here is recovered from
// the provenance object: the index's publisher record, the signing
// certificate and the transparency log entry.
type Extension struct {
	// Publisher is the index's trusted publisher record, verbatim.
	Publisher json.RawMessage `json:"publisher,omitempty"`
	// Distribution identifies the attested file.
	Distribution Distribution `json:"distribution"`
	// Certificate summarizes the Fulcio signing certificate: issuer,
	// subject and the build extensions (source repository and digest,
	// workflow, trigger, run invocation, runner environment).
	Certificate *certificate.Summary `json:"certificate,omitempty"`
	// LoggedAt is the transparency log's integrated time, the moment the
	// attestation was recorded in the log.
	LoggedAt *time.Time `json:"loggedAt,omitempty"`
	// LogIndex is the index of the transparency log entry.
	LogIndex int64 `json:"logIndex,omitempty"`
}

// ParseProvenance decodes a PEP 740 provenance object.
func ParseProvenance(data []byte) (*Provenance, error) {
	prov := &Provenance{}
	if err := json.Unmarshal(data, prov); err != nil {
		return nil, fmt.Errorf("decoding provenance: %w", err)
	}
	if prov.Version != 1 {
		return nil, fmt.Errorf("unsupported provenance version %d", prov.Version)
	}
	return prov, nil
}

// Envelopes converts every attestation of every bundle in the provenance
// object into an envelope for the given distribution file.
func (p *Provenance) Envelopes(dist *Distribution) ([]attestation.Envelope, error) {
	return p.envelopes(dist, false)
}

// envelopes builds the envelopes of the provenance object. When keep is set
// each one keeps, in the origin of its predicate, what it takes to read it
// back (see keepBundle).
func (p *Provenance) envelopes(dist *Distribution, keep bool) ([]attestation.Envelope, error) {
	var ret []attestation.Envelope
	for i := range p.AttestationBundles {
		b := &p.AttestationBundles[i]
		for j := range b.Attestations {
			env, err := buildEnvelope(b.Publisher, &b.Attestations[j], dist)
			if err != nil {
				return nil, fmt.Errorf("bundle %d attestation %d: %w", i, j, err)
			}
			if keep {
				if err := keepBundle(env, b.Publisher, dist); err != nil {
					return nil, fmt.Errorf("keeping bundle %d attestation %d: %w", i, j, err)
				}
			}
			ret = append(ret, env)
		}
	}
	return ret, nil
}

// buildEnvelope reassembles a PEP 740 attestation into a sigstore bundle so
// it verifies through the collector's regular bundle path (DSSE signature,
// certificate chain and transparency log inclusion, all offline).
//
// The statement PyPI signs carries a null predicate, so on its own it says
// nothing a policy can evaluate. When that is the case the bundle is served
// with a synthesized statement instead: same subjects, same predicate type,
// but a predicate carrying the publisher, certificate and log data under
// ExtensionKey. The signed payload is left untouched, so verification still
// runs over the original bytes. A statement with an actual predicate (PyPI
// also accepts SLSA provenance) is served as signed.
func buildEnvelope(publisher json.RawMessage, att *Attestation, dist *Distribution) (attestation.Envelope, error) {
	if att.Version != 1 {
		return nil, fmt.Errorf("unsupported attestation version %d", att.Version)
	}

	statementData, err := base64.StdEncoding.DecodeString(att.Envelope.Statement)
	if err != nil {
		return nil, fmt.Errorf("decoding statement: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(att.Envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	certDER, err := base64.StdEncoding.DecodeString(att.VerificationMaterial.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decoding certificate: %w", err)
	}
	if len(att.VerificationMaterial.TransparencyEntries) == 0 {
		return nil, errors.New("attestation has no transparency log entries")
	}
	entries := make([]*rekorpb.TransparencyLogEntry, 0, len(att.VerificationMaterial.TransparencyEntries))
	for i, raw := range att.VerificationMaterial.TransparencyEntries {
		entry := &rekorpb.TransparencyLogEntry{}
		if err := protojson.Unmarshal(raw, entry); err != nil {
			return nil, fmt.Errorf("decoding transparency log entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}

	mediaType, err := sgbundle.MediaTypeString("v0.3")
	if err != nil {
		return nil, err
	}
	env := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType: mediaType,
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{RawBytes: certDER},
				},
				TlogEntries: entries,
			},
			Content: &protobundle.Bundle_DsseEnvelope{
				DsseEnvelope: &protodsse.Envelope{
					Payload:     statementData,
					PayloadType: intotoPayloadType,
					Signatures:  []*protodsse.Signature{{Sig: signature}},
				},
			},
		},
	}

	signed := &gointoto.Statement{}
	if err := protojson.Unmarshal(statementData, signed); err != nil {
		return nil, fmt.Errorf("decoding signed statement: %w", err)
	}

	// A real predicate is served as signed.
	if signed.GetPredicate() != nil && len(signed.GetPredicate().GetFields()) > 0 {
		return env, nil
	}
	if attestation.PredicateType(signed.GetPredicateType()) != PublishPredicateType {
		return nil, fmt.Errorf("statement has an empty predicate of unexpected type %q", signed.GetPredicateType())
	}

	stmt, err := synthesizeStatement(signed, publisher, certDER, entries[0], dist)
	if err != nil {
		return nil, err
	}
	env.Statement = stmt
	return env, nil
}

// Keys of the reassembly material recorded with the bundle of a synthesized
// statement: what the synthesis reads that is not in the bundle.
const (
	materialPublisher    = "publisher"
	materialDistribution = "distribution"
)

// keepBundle records the sigstore bundle an attestation was reassembled into
// as the origin of its predicate, with the serialized bundle as its content.
//
// The index does not serve a document per attestation: the bundle is built
// here from the fields of the provenance object, so what is kept is that
// bundle as this collector serializes it and the digest of the origin is the
// digest of that serialization, not of anything the index served. It carries
// the signed statement, the certificate and the log entries, so it verifies
// on its own.
//
// When the statement is served as it was signed the bundle is the
// attestation, and it is typed as one. When it was synthesized, parsing the
// bundle gives the statement that was signed and not the one served, so it
// gets no media type: the origin names this repository type instead, with
// the publisher and the distribution the synthesis reads, and Reassemble
// builds the attestation again from them.
func keepBundle(env attestation.Envelope, publisher json.RawMessage, dist *Distribution) error {
	b, ok := env.(*bundle.Envelope)
	if !ok {
		return fmt.Errorf("envelope is not a sigstore bundle (%T)", env)
	}
	pred := env.GetPredicate()
	if pred == nil {
		return errors.New("attestation has no predicate")
	}
	data, err := protojson.Marshal(&b.Bundle)
	if err != nil {
		return fmt.Errorf("serializing bundle: %w", err)
	}
	digests, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil || len(*digests) == 0 {
		return fmt.Errorf("hashing bundle: %w", err)
	}
	origin := digests.ToResourceDescriptors()[0]
	origin.Name = dist.Filename
	origin.Uri = dist.purl()
	origin.Content = data

	signed, err := signedStatement(b)
	if err != nil {
		return err
	}
	if hasPredicate(signed) {
		origin.MediaType = b.GetMediaType()
	} else {
		material, err := reassemblyMaterial(publisher, dist)
		if err != nil {
			return err
		}
		if err := repository.Annotate(origin, TypeMoniker, material); err != nil {
			return err
		}
	}

	pred.SetOrigin(origin)
	return nil
}

// signedStatement decodes the statement a bundle carries, as it was signed.
func signedStatement(b *bundle.Envelope) (*gointoto.Statement, error) {
	signed := &gointoto.Statement{}
	if err := protojson.Unmarshal(b.GetDsseEnvelope().GetPayload(), signed); err != nil {
		return nil, fmt.Errorf("decoding signed statement: %w", err)
	}
	return signed, nil
}

// hasPredicate reports if a signed statement has a predicate of its own. The
// ones that do not are served with a synthesized one.
func hasPredicate(signed *gointoto.Statement) bool {
	return signed.GetPredicate() != nil && len(signed.GetPredicate().GetFields()) > 0
}

// reassemblyMaterial encodes the publisher and the distribution of an
// attestation as the plain values an origin's annotations hold.
func reassemblyMaterial(publisher json.RawMessage, dist *Distribution) (map[string]any, error) {
	material := map[string]any{}
	if len(publisher) > 0 {
		var p any
		if err := json.Unmarshal(publisher, &p); err != nil {
			return nil, fmt.Errorf("decoding publisher: %w", err)
		}
		material[materialPublisher] = p
	}
	data, err := json.Marshal(dist)
	if err != nil {
		return nil, fmt.Errorf("encoding distribution: %w", err)
	}
	var d any
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("encoding distribution: %w", err)
	}
	material[materialDistribution] = d
	return material, nil
}

// Reassemble rebuilds the attestation kept in an origin by this repository
// type: a sigstore bundle whose statement was synthesized. The bundle is
// read from the content, and the statement is synthesized again from it and
// from the publisher and the distribution recorded as reassembly material.
// The envelope verifies as it did when first read: over the signed payload.
func Reassemble(_ context.Context, origin *gointoto.ResourceDescriptor) ([]attestation.Envelope, error) {
	env := &bundle.Envelope{}
	if err := protojson.Unmarshal(origin.GetContent(), &env.Bundle); err != nil {
		return nil, fmt.Errorf("decoding kept bundle: %w", err)
	}
	signed, err := signedStatement(env)
	if err != nil {
		return nil, err
	}
	// Nothing to synthesize: the bundle is the attestation
	if hasPredicate(signed) {
		return []attestation.Envelope{env}, nil
	}

	material := repository.Material(origin)
	if material == nil {
		return nil, errors.New("origin has no reassembly material")
	}
	dist := &Distribution{}
	data, err := json.Marshal(material[materialDistribution])
	if err != nil {
		return nil, fmt.Errorf("reading distribution: %w", err)
	}
	if err := json.Unmarshal(data, dist); err != nil {
		return nil, fmt.Errorf("reading distribution: %w", err)
	}
	if dist.Filename == "" {
		return nil, errors.New("reassembly material names no distribution file")
	}
	var publisher json.RawMessage
	if p, ok := material[materialPublisher]; ok {
		if publisher, err = json.Marshal(p); err != nil {
			return nil, fmt.Errorf("reading publisher: %w", err)
		}
	}

	certDER := env.GetVerificationMaterial().GetCertificate().GetRawBytes()
	entries := env.GetVerificationMaterial().GetTlogEntries()
	if len(certDER) == 0 || len(entries) == 0 {
		return nil, errors.New("kept bundle has no certificate or transparency log entry")
	}

	stmt, err := synthesizeStatement(signed, publisher, certDER, entries[0], dist)
	if err != nil {
		return nil, err
	}
	env.Statement = stmt
	return []attestation.Envelope{env}, nil
}

// synthesizeStatement builds the statement served in place of a signed
// statement whose predicate is null.
func synthesizeStatement(signed *gointoto.Statement, publisher json.RawMessage, certDER []byte, entry *rekorpb.TransparencyLogEntry, dist *Distribution) (*intoto.Statement, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parsing signing certificate: %w", err)
	}
	summary, err := certificate.SummarizeCertificate(cert)
	if err != nil {
		return nil, fmt.Errorf("summarizing signing certificate: %w", err)
	}

	ext := Extension{
		Publisher:    publisher,
		Distribution: *dist,
		Certificate:  &summary,
		LogIndex:     entry.GetLogIndex(),
	}
	if entry.GetIntegratedTime() != 0 {
		t := time.Unix(entry.GetIntegratedTime(), 0).UTC()
		ext.LoggedAt = &t
	}

	parsed := map[string]any{ExtensionKey: ext}
	data, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("marshaling predicate: %w", err)
	}

	pred := &generic.Predicate{
		Type:   PublishPredicateType,
		Data:   data,
		Parsed: parsed,
	}

	// The signed subjects name the file and carry its digest. Add the
	// file's package URL so the attestation also matches by purl.
	subjects := make([]*gointoto.ResourceDescriptor, 0, len(signed.GetSubject()))
	for _, s := range signed.GetSubject() {
		if s.GetUri() == "" {
			s.Uri = dist.purl()
		}
		subjects = append(subjects, s)
	}

	return intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(subjects...),
	), nil
}
