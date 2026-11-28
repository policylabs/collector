// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

// Package maven implements an attestation collector that fetches attestations
// from Maven repository directory listings. It looks for PGP signatures (.asc),
// JSONL attestation bundles, and unsigned SBOMs (.spdx.json, .cdx.json).
package maven

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/hasher"
	gopurl "github.com/package-url/packageurl-go"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	"github.com/policylabs/signer/key"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/release-utils/http"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/filters"
	"github.com/policylabs/collector/internal/readlimit"
	"github.com/policylabs/collector/predicate/generic"
	"github.com/policylabs/collector/repository/filesystem"
	"github.com/policylabs/collector/statement/intoto"
)

var TypeMoniker = "maven"

// Build is the factory function used to register the collector.
// The init string is a maven purl, e.g. "pkg:maven/com.aliyun/foo@1.0".
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithPackageURL(istr))
}

var (
	_ attestation.Fetcher                = (*Collector)(nil)
	_ attestation.FetcherBySubject       = (*Collector)(nil)
	_ attestation.FetcherByPredicateType = (*Collector)(nil)
)

// Collector fetches attestations from a Maven repository directory listing.
type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
}

// New creates a new Maven collector.
func New(funcs ...optFn) (*Collector, error) {
	c := &Collector{
		Options: defaultOptions,
	}
	for _, fn := range funcs {
		if err := fn(c); err != nil {
			return nil, err
		}
	}
	if err := c.Options.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}
	return c, nil
}

// SetKeys sets the verification keys on the collector.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch retrieves attestations for the configured package URL. When the
// collector is in global mode (no package URL configured) it returns
// nothing — global mode is subject-driven, use FetchBySubject instead.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if !c.Options.HasPackageURL() {
		return nil, nil
	}
	// In configured mode the collector's BaseURL is authoritative — it
	// already reflects any "repository_url" qualifier captured at
	// construction time and preserves explicit WithBaseURL overrides.
	return c.fetchForPurl(ctx, opts, &c.Options.PackageURL, c.Options.BaseURL)
}

// fetchForPurl runs the full attestation lookup for a single Maven purl
// against the supplied base URL. Callers own the base-URL policy:
// configured mode passes the collector's BaseURL as-is; global mode
// resolves per-subject via baseURLForPurl so a "repository_url"
// qualifier on a subject purl can target its own repository.
func (c *Collector) fetchForPurl(ctx context.Context, opts attestation.FetchOptions, purl *gopurl.PackageURL, baseURL string) ([]attestation.Envelope, error) {
	dirURL := directoryURL(purl, baseURL)
	artifactID := purl.Name
	agent := http.NewAgent().WithFailOnHTTPError(true)

	md, err := c.fetchMetadata(ctx, agent, dirURL)
	if err != nil {
		return nil, err
	}

	var ret []attestation.Envelope

	ascEnvs, err := c.fetchSignature(ctx, agent, dirURL, purl, md, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, ascEnvs...)

	jsonlEnvs, err := c.fetchJSONLAttestations(ctx, agent, dirURL, artifactID, md, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, jsonlEnvs...)

	sbomEnvs, err := c.fetchSBOMs(ctx, agent, dirURL, artifactID, md, opts)
	if err != nil {
		return nil, err
	}
	ret = append(ret, sbomEnvs...)

	if opts.Query != nil {
		ret = opts.Query.Run(ret)
	}

	if opts.Limit > 0 && len(ret) > opts.Limit {
		ret = ret[:opts.Limit]
	}

	return ret, nil
}

// FetchBySubject collects attestations for each subject. In configured
// mode it fetches once for the configured purl and filters by subject
// digest. In global mode it extracts Maven purls from subjects (via the
// Uri or Name field of the resource descriptor), fetches for each, and
// filters the union by the requested digests.
func (c *Collector) FetchBySubject(ctx context.Context, opts attestation.FetchOptions, subj []attestation.Subject) ([]attestation.Envelope, error) {
	var all []attestation.Envelope

	if c.Options.HasPackageURL() {
		envs, err := c.Fetch(ctx, opts)
		if err != nil {
			return nil, err
		}
		all = envs
	} else {
		purls := extractMavenPurls(subj)
		for i := range purls {
			p := &purls[i]
			// Global mode: a per-subject purl can carry its own
			// "repository_url" qualifier; fall back to the collector's
			// BaseURL when it doesn't.
			envs, err := c.fetchForPurl(ctx, opts, p, baseURLForPurl(p, c.Options.BaseURL))
			if err != nil {
				// A missing or unreachable package for one subject shouldn't
				// fail the whole query — log and continue.
				logrus.Debugf("maven: skipping %s: %v", p.String(), err)
				continue
			}
			all = append(all, envs...)
		}
	}

	m := make([]map[string]string, 0, len(subj))
	for _, s := range subj {
		m = append(m, s.GetDigest())
	}

	return attestation.NewQuery().WithFilter(&filters.SubjectHashMatcher{
		HashSets: m,
	}).Run(all), nil
}

// FetchByPredicateType handles collecting by predicate type. It requires
// a configured package URL — global mode is subject-driven and has no
// per-predicate-type entry point.
func (c *Collector) FetchByPredicateType(ctx context.Context, opts attestation.FetchOptions, pts []attestation.PredicateType) ([]attestation.Envelope, error) {
	if !c.Options.HasPackageURL() {
		return nil, nil
	}
	all, err := c.Fetch(ctx, opts)
	if err != nil {
		return nil, err
	}

	m := map[attestation.PredicateType]struct{}{}
	for _, pt := range pts {
		m[pt] = struct{}{}
	}

	return attestation.NewQuery().WithFilter(&filters.PredicateTypeMatcher{
		PredicateTypes: m,
	}).Run(all), nil
}

// extractMavenPurls reads Maven package URLs from the Uri and Name fields
// of the provided subjects. Non-Maven or unparseable purls are ignored,
// and duplicates are deduplicated. The slice owns its elements — callers
// that need a pointer should address into the slice (&purls[i]).
func extractMavenPurls(subjects []attestation.Subject) []gopurl.PackageURL {
	seen := map[string]struct{}{}
	var ret []gopurl.PackageURL
	for _, s := range subjects {
		for _, candidate := range []string{s.GetUri(), s.GetName()} {
			if !strings.HasPrefix(candidate, "pkg:") {
				continue
			}
			p, err := gopurl.FromString(candidate)
			if err != nil {
				continue
			}
			if err := validateMavenPurl(&p); err != nil {
				continue
			}
			id := p.String()
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ret = append(ret, p)
		}
	}
	return ret
}

// mavenMetadata represents the relevant parts of maven-metadata.xml.
type mavenMetadata struct {
	XMLName    xml.Name        `xml:"metadata"`
	Versioning mavenVersioning `xml:"versioning"`
}

type mavenVersioning struct {
	SnapshotVersions []snapshotVersion `xml:"snapshotVersions>snapshotVersion"`
}

type snapshotVersion struct {
	Classifier string `xml:"classifier"`
	Extension  string `xml:"extension"`
	Value      string `xml:"value"`
}

// fetchMetadata fetches and parses the maven-metadata.xml from the directory.
func (c *Collector) fetchMetadata(ctx context.Context, agent *http.Agent, dirURL string) (*mavenMetadata, error) {
	data, err := agent.GetContext(ctx, dirURL+"maven-metadata.xml")
	if err != nil {
		return nil, fmt.Errorf("fetching maven-metadata.xml from %s: %w", dirURL, err)
	}

	var md mavenMetadata
	if err := xml.Unmarshal(data, &md); err != nil {
		return nil, fmt.Errorf("parsing maven-metadata.xml: %w", err)
	}

	return &md, nil
}

// resolveFilename builds the artifact filename from metadata.
// For a snapshotVersion with classifier="cyclonedx", extension="json",
// value="3.21.0.slsa-20260403.173453-4", artifactID="commons-lang3":
// → commons-lang3-3.21.0.slsa-20260403.173453-4-cyclonedx.json
func resolveFilename(artifactID string, sv snapshotVersion) string {
	name := artifactID + "-" + sv.Value
	if sv.Classifier != "" {
		name += "-" + sv.Classifier
	}
	return name + "." + sv.Extension
}

// findSnapshotVersion looks up a snapshotVersion entry by extension and classifier.
func findSnapshotVersion(md *mavenMetadata, extension, classifier string) (snapshotVersion, bool) {
	for _, sv := range md.Versioning.SnapshotVersions {
		if sv.Extension == extension && sv.Classifier == classifier {
			return sv, true
		}
	}
	return snapshotVersion{}, false
}

// fetchSignature looks for the purl-identified artifact's .asc in the
// metadata, fetches both the artifact and its signature, and verifies using
// loaded keys. The artifact extension and classifier are taken from the
// purl "type" and "classifier" qualifiers so the hashed subject matches
// the artifact the purl refers to. Returns nil without error if the
// artifacts are not in the metadata or no keys are configured.
func (c *Collector) fetchSignature(ctx context.Context, agent *http.Agent, dirURL string, purl *gopurl.PackageURL, md *mavenMetadata, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	if len(c.Keys) == 0 {
		return nil, nil
	}

	artifactID := purl.Name
	artType := artifactType(purl)
	classifier := artifactClassifier(purl)

	artSV, artOK := findSnapshotVersion(md, artType, classifier)
	ascSV, ascOK := findSnapshotVersion(md, artType+".asc", classifier)
	if !artOK || !ascOK {
		return nil, nil
	}

	// The artifact and its signature must resolve to the same version to
	// prevent replay attacks where an old valid signature is paired with
	// a newer artifact.
	if artSV.Value != ascSV.Value {
		return nil, nil
	}

	artFile := resolveFilename(artifactID, artSV)
	ascFile := resolveFilename(artifactID, ascSV)
	maxSize := readlimit.Resolve(opts.MaxReadSize)

	// Fetch the artifact and its signature in parallel.
	urls := []string{dirURL + artFile, dirURL + ascFile}
	datas, errs := agent.GetGroupContext(ctx, urls)

	for i, e := range errs {
		if e != nil {
			return nil, fmt.Errorf("fetching %s: %w", urls[i], e)
		}
	}

	artData, sigData := datas[0], datas[1]

	if int64(len(artData)) > maxSize {
		return nil, fmt.Errorf("artifact %s exceeds max read size (%d bytes)", artFile, maxSize)
	}

	// Verify signature using loaded keys. Verification failure is not
	// a fetch error — the signature simply didn't match any loaded key.
	verification, verifyErr := verifyWithKeys(c.Keys, artData, sigData)
	if verifyErr != nil {
		return nil, nil //nolint:nilerr // verification failure is not a fetch error
	}

	env, err := buildVirtualAttestation(artFile, artData, verification)
	if err != nil {
		return nil, fmt.Errorf("building signature attestation for %s: %w", artFile, err)
	}

	return []attestation.Envelope{env}, nil
}

// fetchJSONLAttestations looks for intoto.jsonl in the metadata and parses
// it for attestation envelopes. Returns nil without error if not present.
func (c *Collector) fetchJSONLAttestations(ctx context.Context, agent *http.Agent, dirURL, artifactID string, md *mavenMetadata, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	sv, ok := findSnapshotVersion(md, "intoto.jsonl", "")
	if !ok {
		return nil, nil
	}

	filename := resolveFilename(artifactID, sv)
	maxSize := readlimit.Resolve(opts.MaxReadSize)

	data, err := agent.GetContext(ctx, dirURL+filename)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", filename, err)
	}

	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("JSONL file %s exceeds max read size (%d bytes)", filename, maxSize)
	}

	return (&envelope.JsonlParser{KeepContent: opts.KeepContent}).Parse(data)
}

// sbomExtensions lists the metadata extensions we recognize as SBOMs,
// along with the classifier (empty string means no classifier).
var sbomExtensions = []struct {
	extension  string
	classifier string
}{
	{"spdx.json", ""},
	{"cdx.json", ""},
	{"json", "cyclonedx"},
}

// fetchSBOMs looks for unsigned SBOM files in the metadata.
// Returns nil without error if none are present.
func (c *Collector) fetchSBOMs(ctx context.Context, agent *http.Agent, dirURL, artifactID string, md *mavenMetadata, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	maxSize := readlimit.Resolve(opts.MaxReadSize)
	var ret []attestation.Envelope

	for _, ext := range sbomExtensions {
		sv, ok := findSnapshotVersion(md, ext.extension, ext.classifier)
		if !ok {
			continue
		}

		filename := resolveFilename(artifactID, sv)
		data, err := agent.GetContext(ctx, dirURL+filename)
		if err != nil {
			return nil, fmt.Errorf("fetching SBOM %s: %w", filename, err)
		}

		if int64(len(data)) > maxSize {
			return nil, fmt.Errorf("SBOM %s exceeds max read size (%d bytes)", filename, maxSize)
		}

		envs, err := envelope.Parsers.Parse(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parsing SBOM %s: %w", filename, err)
		}
		if opts.KeepContent {
			envelope.KeepContent(envs, data)
		}

		ret = append(ret, envs...)
	}

	return ret, nil
}

// verifyWithKeys attempts to verify a raw signature against artifact data
// using the provided keys.
func verifyWithKeys(keys []key.PublicKeyProvider, artifactData, sigData []byte) (*sapi.Verification, error) {
	verifier := key.NewVerifier()
	var identities []*sapi.Identity

	for _, pkp := range keys {
		verified, err := verifier.VerifyMessage(pkp, artifactData, sigData)
		if err != nil {
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

// buildVirtualAttestation creates a predicate-less virtual attestation
// for a verified signature, hashing the artifact to form the subject.
func buildVirtualAttestation(artifactName string, artifactData []byte, verification *sapi.Verification) (attestation.Envelope, error) {
	hsets, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(artifactData)})
	if err != nil {
		return nil, fmt.Errorf("hashing artifact: %w", err)
	}

	rds := hsets.ToResourceDescriptors()
	if len(rds) == 0 {
		return nil, fmt.Errorf("no hash computed for artifact")
	}

	rd := rds[0]
	rd.Name = artifactName

	pred := &generic.Predicate{
		Type:         filesystem.SignaturePredicateType,
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
// attestations, matching the pattern used by the filesystem collector.
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
