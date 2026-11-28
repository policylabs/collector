// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/carabiner-dev/hasher"
	"github.com/gogo/protobuf/jsonpb"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	"github.com/policylabs/attestation"
	"github.com/policylabs/signer/key"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	cenvelope "github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/envelope/dsse"
	"github.com/policylabs/collector/internal/readlimit"
)

var TypeMoniker = "coci"

// ImageInfo contains parsed information about a container image reference
type ImageInfo struct {
	OriginalRef string
	Registry    string
	Repository  string
	Tag         string
	Digest      string
	Identifier  string
	IsDigest    bool
}

func parseImageReference(ctx context.Context, ref string, opts ...crane.Option) (*ImageInfo, error) {
	parsedRef, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %w", err)
	}

	info := &ImageInfo{
		OriginalRef: ref,
		Registry:    parsedRef.Context().RegistryStr(),
		Repository:  parsedRef.Context().RepositoryStr(),
		Identifier:  parsedRef.Identifier(),
	}

	// Check if it's a tag or digest reference
	switch v := parsedRef.(type) {
	case name.Tag:
		info.Tag = v.TagStr()
		info.IsDigest = false

		digestOpts := append([]crane.Option{crane.WithContext(ctx)}, opts...)
		digest, err := crane.Digest(ref, digestOpts...)
		if err != nil {
			return nil, fmt.Errorf("getting reference digest: %w", err)
		}
		info.Digest = digest
	case name.Digest:
		info.Digest = v.DigestStr()
		info.IsDigest = true
	}

	return info, nil
}

// Implement the factory function
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReference(istr))
}

var _ attestation.Fetcher = (*Collector)(nil)

func New(funcs ...optFn) (*Collector, error) {
	// Apply the functional options
	opts := defaultOptions
	for _, fn := range funcs {
		if err := fn(&opts); err != nil {
			return nil, err
		}
	}

	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validating options: %w", err)
	}

	return &Collector{
		Options: opts,
	}, nil
}

type (
	optFn   = func(*Options) error
	Options struct {
		Reference string
		craneOpts []crane.Option

		// The three tags cosign's legacy layout hangs off an image digest,
		// each of which can be switched off. All are read by default.
		ReadAttestations bool // `.att`: DSSE attestation layers
		ReadSignatures   bool // `.sig`: cosign signature layers
		ReadSBOMs        bool // `.sbom`: SBOM document layers
	}
)

func WithReference(ref string) optFn {
	return func(o *Options) error {
		_, err := name.ParseReference(ref)
		if err != nil {
			return err
		}
		o.Reference = ref // perhaps parse?
		return nil
	}
}

// WithCraneOpts sets crane options that are applied to all registry calls
// made by the collector (e.g. crane.Insecure for an HTTP test registry, or
// custom auth/transport).
func WithCraneOpts(opts ...crane.Option) optFn {
	return func(o *Options) error {
		o.craneOpts = append(o.craneOpts, opts...)
		return nil
	}
}

// WithReadAttestations controls whether the `.att` attestation layers are
// read. On by default.
func WithReadAttestations(doit bool) optFn {
	return func(o *Options) error {
		o.ReadAttestations = doit
		return nil
	}
}

// WithReadSignatures controls whether the `.sig` signature layers are read.
// On by default.
func WithReadSignatures(doit bool) optFn {
	return func(o *Options) error {
		o.ReadSignatures = doit
		return nil
	}
}

// WithReadSBOMs controls whether the `.sbom` SBOM layers are read. On by
// default.
func WithReadSBOMs(doit bool) optFn {
	return func(o *Options) error {
		o.ReadSBOMs = doit
		return nil
	}
}

func (o *Options) Validate() error {
	return nil
}

var defaultOptions = Options{
	ReadAttestations: true,
	ReadSignatures:   true,
	ReadSBOMs:        true,
}

type Collector struct {
	Options Options
	Keys    []key.PublicKeyProvider
}

// craneOpts returns the crane options configured on the collector. It exists
// as a method (rather than direct field access) so Fetch / Store call sites
// can always start from a fresh slice.
func (c *Collector) craneOpts() []crane.Option {
	if len(c.Options.craneOpts) == 0 {
		return nil
	}
	out := make([]crane.Option, len(c.Options.craneOpts))
	copy(out, c.Options.craneOpts)
	return out
}

// SetKeys sets the verification keys used by the collector.
func (c *Collector) SetKeys(keys []key.PublicKeyProvider) {
	c.Keys = keys
}

// Fetch queries the repository and retrieves any attestations matching the query
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	imageInfo, err := parseImageReference(ctx, c.Options.Reference, c.craneOpts()...)
	if err != nil {
		return nil, err
	}

	// Fetch the enabled tags (.att attestation layers, .sig signature
	// layers and .sbom SBOM layers) concurrently.
	var (
		attAtts, sigAtts, sbomAtts []attestation.Envelope
		attErr, sigErr, sbomErr    error
		wg                         sync.WaitGroup
	)

	if c.Options.ReadAttestations {
		wg.Add(1)
		go func() {
			defer wg.Done()
			attAtts, attErr = c.fetchAttestationLayers(ctx, opts, imageInfo)
		}()
	}
	if c.Options.ReadSignatures {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sigAtts, sigErr = c.fetchSignatures(ctx, opts, imageInfo)
		}()
	}
	if c.Options.ReadSBOMs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sbomAtts, sbomErr = c.fetchSBOMLayers(ctx, opts, imageInfo)
		}()
	}
	wg.Wait()

	if attErr != nil {
		return nil, attErr
	}

	atts := attAtts
	if sigErr != nil {
		logrus.Debugf("coci: fetching .sig image: %v", sigErr)
	} else {
		atts = append(atts, sigAtts...)
	}
	if sbomErr != nil {
		logrus.Debugf("coci: fetching .sbom image: %v", sbomErr)
	} else {
		atts = append(atts, sbomAtts...)
	}

	return atts, nil
}

// fetchAttestationLayers fetches the .att manifest and pulls all DSSE layers
// in parallel.
func (c *Collector) fetchAttestationLayers(ctx context.Context, opts attestation.FetchOptions, imageInfo *ImageInfo) ([]attestation.Envelope, error) {
	manifestData, err := crane.Manifest(
		fmt.Sprintf(
			"%s/%s:%s.att",
			imageInfo.Registry, imageInfo.Repository,
			strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
		),
		append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)...,
	)
	if err != nil {
		// A missing .att manifest simply means the image has no attestations
		// attached yet. Treat it as an empty result instead of an error.
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching attestations manifest: %w", err)
	}

	manifest, err := ggcr.ParseManifest(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parsing attestations manifest: %w", err)
	}

	// Identify DSSE layers to fetch.
	type indexedLayer struct {
		index int
		layer *ggcr.Descriptor
	}
	var dsseLayers []indexedLayer
	for i := range manifest.Layers {
		if manifest.Layers[i].MediaType == "application/vnd.dsse.envelope.v1+json" {
			dsseLayers = append(dsseLayers, indexedLayer{i, &manifest.Layers[i]})
		}
	}

	// Pull layers in parallel (up to 10 concurrent pulls).
	type layerResult struct {
		envelope attestation.Envelope
		err      error
		index    int
	}
	results := make([]layerResult, len(dsseLayers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for j, dl := range dsseLayers {
		wg.Add(1)
		go func(j int, dl indexedLayer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			envelope, err := getAttestationEnvelope(ctx, &opts, imageInfo, dl.layer, c.craneOpts()...)
			results[j] = layerResult{envelope, err, dl.index}
		}(j, dl)
	}
	wg.Wait()

	// Collect results preserving layer order.
	var atts []attestation.Envelope
	for _, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("generating envelope from layer %d: %w", r.index, r.err)
		}
		if r.envelope.GetStatement() == nil {
			logrus.Debugf("coci: skipping layer %d: payload could not be parsed into a statement", r.index)
			continue
		}
		atts = append(atts, r.envelope)
		if opts.Limit > 0 && len(atts) >= opts.Limit {
			break
		}
	}

	return atts, nil
}

// dsseEnvelopeFromOCILayer reads the DSSE envelope containing the attestation
// from a layer. The data of the layer is returned with the envelope parsed
// from it.
func dsseEnvelopeFromOCILayer(ctx context.Context, opts *attestation.FetchOptions, imageInfo *ImageInfo, l *ggcr.Descriptor, craneOpts ...crane.Option) (*protobundle.Bundle_DsseEnvelope, []byte, error) {
	// Build the attestation blob reference
	attRef := imageInfo.Registry + "/" + imageInfo.Repository + "@" + l.Digest.String()
	layer, err := crane.PullLayer(attRef, append([]crane.Option{crane.WithContext(ctx)}, craneOpts...)...)
	if err != nil {
		return nil, nil, fmt.Errorf("pulling layer data: %w", err)
	}

	// Parse the DSSE envelop from the signed contents
	blob, err := layer.Uncompressed()
	if err != nil {
		return nil, nil, fmt.Errorf("fetching blob data: %w", err)
	}
	defer blob.Close() //nolint:errcheck

	data, err := io.ReadAll(readlimit.Reader(blob, opts.MaxReadSize))
	if err != nil {
		return nil, nil, fmt.Errorf("reading blob data: %w", err)
	}

	unmarshaler := jsonpb.Unmarshaler{}

	// Unmarshal the data
	dsseEnv := &protodsse.Envelope{}
	if err := unmarshaler.Unmarshal(bytes.NewReader(data), dsseEnv); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling dsse envelope: %w", err)
	}

	// Return the wrapped envelope
	return &protobundle.Bundle_DsseEnvelope{DsseEnvelope: dsseEnv}, data, nil
}

// Some of these functions were adapted to verify DSSE envelopes form the handy
// image verification example in:
// https://github.com/sigstore/sigstore-go/blob/8997a46ef2bef0f88b9e3aef1c45b6dbc0096b55/examples/oci-image-verification/main.go

func verificationMaterialFromOCILayer(layer *ggcr.Descriptor) (*protobundle.VerificationMaterial, error) {
	certData, ok := layer.Annotations["dev.sigstore.cosign/certificate"]
	if !ok {
		return nil, errors.New("certificate not found in layer data")
	}

	block, _ := pem.Decode([]byte(certData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	certs := &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}

	// 2. Get the transparency log entries
	tlogEntries, err := getVerificationMaterialTlogEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("error getting tlog entries: %w", err)
	}

	timestampEntries, err := getVerificationMaterialTimestampEntries(layer)
	if err != nil {
		return nil, fmt.Errorf("error getting timestamp entries: %w", err)
	}

	// 3. Construct the verification material
	return &protobundle.VerificationMaterial{
		Content:                   certs,
		TlogEntries:               tlogEntries,
		TimestampVerificationData: timestampEntries,
	}, nil
}

func getVerificationMaterialTimestampEntries(manifestLayer *ggcr.Descriptor) (*protobundle.TimestampVerificationData, error) {
	// 1. Get the bundle annotation
	ts, ok := manifestLayer.Annotations["dev.sigstore.cosign/rfc3161timestamp"]
	if !ok {
		return nil, nil
	}
	// 2. Get the key/value pairs maps
	var keyValPairs map[string]string
	err := json.Unmarshal([]byte(ts), &keyValPairs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling JSON blob into key/val map: %w", err)
	}
	// 3. Verify the key "SignedRFC3161Timestamp" is present
	if _, ok := keyValPairs["SignedRFC3161Timestamp"]; !ok {
		return nil, errors.New("error getting SignedRFC3161Timestamp from key/value pairs")
	}
	// 4. Decode the base64 encoded timestamp
	der, err := base64.StdEncoding.DecodeString(keyValPairs["SignedRFC3161Timestamp"])
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 encoded timestamp: %w", err)
	}
	// 4. Construct the timestamp entry list
	return &protobundle.TimestampVerificationData{
		Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
			{
				SignedTimestamp: der,
			},
		},
	}, nil
}

// getAttestationEnvelope reads a DSSE layer from the OCI image and returns an
// attestation envelope. If the layer contains cosign verification material
// (certificate, tlog entries, etc.) a full sigstore bundle is returned.
// Otherwise the payload is returned as a plain DSSE envelope that can be
// verified with a public key.
func getAttestationEnvelope(ctx context.Context, opts *attestation.FetchOptions, imageInfo *ImageInfo, layer *ggcr.Descriptor, craneOpts ...crane.Option) (attestation.Envelope, error) {
	dsseEnv, layerData, err := dsseEnvelopeFromOCILayer(ctx, opts, imageInfo, layer, craneOpts...)
	if err != nil {
		return nil, fmt.Errorf("error getting dsse envelope from layer: %w", err)
	}

	originURI := fmt.Sprintf(
		"oci:%s/%s:%s.att", imageInfo.Registry, imageInfo.Repository,
		strings.Replace(layer.Digest.String(), "sha256:", "sha256-", 1),
	)

	material, err := verificationMaterialFromOCILayer(layer)
	if err != nil {
		// No usable verification material. Fall back to a plain DSSE
		// envelope so the attestation is still returned and can be
		// verified with a public key.
		logrus.Debugf("coci: no verification material in layer, falling back to plain DSSE: %v", err)
		// The layer is the attestation: it is what gets kept
		if !opts.KeepContent {
			layerData = nil
		}
		return buildPlainDSSEEnvelope(dsseEnv, originURI, layerData)
	}

	mt, err := sbundle.MediaTypeString("v0.3")
	if err != nil {
		return nil, err
	}

	envelope := &bundle.Envelope{
		Bundle: protobundle.Bundle{
			MediaType:            mt,
			VerificationMaterial: material,
			Content:              dsseEnv,
		},
	}

	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(dsseEnv.DsseEnvelope.GetPayload())})
	if err != nil {
		return nil, fmt.Errorf("hashing dsse envelope: %w", err)
	}

	origin := hset.ToResourceDescriptors()
	origin[0].Uri = originURI

	// The payload may not be a parseable in-toto statement (for example an
	// attestation whose predicate is not a JSON object). Return the envelope
	// as is and let the caller decide what to do with it.
	if pred := envelope.GetPredicate(); pred != nil {
		pred.SetOrigin(origin[0])

		// The bundle is put together here, from the layer and from the
		// verification material in its annotations: no single piece of
		// data read is the attestation. What is kept is the bundle as it
		// serializes, which verifies on its own.
		if opts.KeepContent {
			data, err := protojson.Marshal(&envelope.Bundle)
			if err != nil {
				return nil, fmt.Errorf("serializing bundle: %w", err)
			}
			if err := cenvelope.KeepData(envelope, data, envelope.GetMediaType()); err != nil {
				return nil, fmt.Errorf("keeping bundle: %w", err)
			}
		}
	}

	return envelope, nil
}

// buildPlainDSSEEnvelope wraps a raw DSSE protobuf envelope into the
// collector's dsse.Envelope type so it can be returned without sigstore
// verification material and verified with a public key instead.
//
// When keep, the data of the layer the envelope was read from, is not empty
// it is kept as the content of the origin of the attestation.
func buildPlainDSSEEnvelope(dsseEnv *protobundle.Bundle_DsseEnvelope, originURI string, keep []byte) (attestation.Envelope, error) {
	env := &dsse.Envelope{
		Envelope: dsseEnv.DsseEnvelope,
	}

	for _, s := range dsseEnv.DsseEnvelope.GetSignatures() {
		env.Signatures = append(env.Signatures, &dsse.Signature{
			KeyID:     s.GetKeyid(),
			Signature: s.GetSig(),
		})
	}

	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(dsseEnv.DsseEnvelope.GetPayload())})
	if err != nil {
		return nil, fmt.Errorf("hashing dsse envelope: %w", err)
	}

	origin := hset.ToResourceDescriptors()
	origin[0].Uri = originURI
	if pred := env.GetPredicate(); pred != nil {
		pred.SetOrigin(origin[0])
		if len(keep) > 0 {
			if err := cenvelope.KeepData(env, keep, dsse.MediaType); err != nil {
				return nil, fmt.Errorf("keeping envelope: %w", err)
			}
		}
	}

	return env, nil
}

// getVerificationMaterialTlogEntries returns any transparency log entries found in the layer
func getVerificationMaterialTlogEntries(manifestLayer *ggcr.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	bun, ok := manifestLayer.Annotations["dev.sigstore.cosign/bundle"]
	if !ok {
		return nil, fmt.Errorf("unable to find bundle annotation in layer")
	}

	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(bun), &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	if _, ok := jsonData["Payload"]; !ok {
		return []*protorekor.TransparencyLogEntry{}, nil
	}
	if _, ok := jsonData["SignedEntryTimestamp"]; !ok {
		return []*protorekor.TransparencyLogEntry{}, nil
	}

	// Log index, log ID, integrated time, signed entry timestamp and body
	set, ok := jsonData["SignedEntryTimestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting SignedEntryTimestamp")
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(set)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}

	logIndex, ok := jsonData["Payload"].(map[string]interface{})["logIndex"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting logIndex")
	}
	li, ok := jsonData["Payload"].(map[string]interface{})["logID"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting logID")
	}
	logID, err := hex.DecodeString(li)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	integratedTime, ok := jsonData["Payload"].(map[string]interface{})["integratedTime"].(float64)
	if !ok {
		return nil, fmt.Errorf("error getting integratedTime")
	}

	// 3. Unmarshal the body and extract the rekor KindVersion details
	body, ok := jsonData["Payload"].(map[string]interface{})["body"].(string)
	if !ok {
		return nil, fmt.Errorf("error getting body")
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("error decoding body: %w", err)
	}
	err = json.Unmarshal(bodyBytes, &jsonData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling json: %w", err)
	}

	var apiVersion, kind string
	if v, ok := jsonData["apiVersion"].(string); ok {
		apiVersion = v
	}

	if v, ok := jsonData["kind"].(string); ok {
		kind = v
	}

	// 4. Construct the transparency log entry list
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(logIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    kind,
				Version: apiVersion,
			},
			IntegratedTime: int64(integratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			InclusionProof:    nil,
			CanonicalizedBody: bodyBytes,
		},
	}, nil
}
