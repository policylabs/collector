// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/policylabs/attestation"
	"github.com/regclient/regclient"
	"github.com/regclient/regclient/types/descriptor"
	"github.com/regclient/regclient/types/manifest"
	"github.com/regclient/regclient/types/ref"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/envelope/bundle"
	"github.com/policylabs/collector/internal/readlimit"
	"github.com/policylabs/collector/repository"
)

const (
	TypeMoniker = "oci"
	// sigstoreBundleArtifactType is the artifact type for sigstore bundles
	// attached as OCI referrers by cosign v3.
	sigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

// Build is the factory function used to register this collector.
var Build = func(istr string) (attestation.Repository, error) {
	return New(WithReference(istr))
}

var (
	_ attestation.Fetcher = (*Collector)(nil)
	_ attestation.Storer  = (*Collector)(nil)
)

// Collector fetches sigstore bundle attestations attached as OCI referrers.
type Collector struct {
	Options Options
}

// New creates a new OCI referrers collector.
func New(funcs ...optFn) (*Collector, error) {
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

// Fetch queries the OCI referrers for the configured image and returns any
// sigstore bundle attestations found.
func (c *Collector) Fetch(ctx context.Context, opts attestation.FetchOptions) ([]attestation.Envelope, error) {
	r, err := ref.New(c.Options.Reference)
	if err != nil {
		return nil, fmt.Errorf("parsing reference: %w", err)
	}

	rc := c.newRegClient()

	// Resolve tag to digest so we can query referrers.
	if r.Digest == "" {
		m, err := rc.ManifestHead(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("resolving reference digest: %w", err)
		}
		r = r.SetDigest(m.GetDescriptor().Digest.String())
	}

	// Fetch all referrers without filtering by artifact type. Some registries
	// (notably GHCR) do not propagate the manifest-level artifactType into the
	// referrer descriptor, so an API-level filter would miss valid entries.
	rl, err := rc.ReferrerList(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("listing referrers: %w", err)
	}

	var atts []attestation.Envelope
	parser := bundle.Parser{}

	for i := range rl.Descriptors {
		envs, err := c.fetchReferrer(ctx, rc, &r, &rl.Descriptors[i], &opts, &parser)
		if err != nil {
			logrus.Debugf("oci: skipping referrer %d: %v", i, err)
			continue
		}
		atts = append(atts, envs...)

		if opts.Limit > 0 && len(atts) >= opts.Limit {
			break
		}
	}

	return atts, nil
}

// newRegClient builds a regclient using the configured overrides or sensible
// defaults that read credentials from the Docker config.
func (c *Collector) newRegClient() *regclient.RegClient {
	rcOpts := c.Options.regOpts
	if len(rcOpts) == 0 {
		rcOpts = []regclient.Opt{regclient.WithDockerCreds(), regclient.WithDockerCerts()}
	}
	return regclient.New(rcOpts...)
}

// Store implements the attestation.Storer interface. Each envelope is uploaded
// as a sigstore bundle artifact attached to the configured image via the OCI
// referrers API. Envelopes are expected to marshal as sigstore bundles (e.g.
// *bundle.Envelope); other envelope types will be uploaded as-is and may not
// be retrievable by sigstore-aware verifiers.
func (c *Collector) Store(ctx context.Context, _ attestation.StoreOptions, envelopes []attestation.Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}

	r, err := ref.New(c.Options.Reference)
	if err != nil {
		return fmt.Errorf("parsing reference: %w", err)
	}

	rc := c.newRegClient()

	// Resolve the subject manifest so we can build a referrer pointing at it.
	subjMan, err := rc.ManifestHead(ctx, r)
	if err != nil {
		return fmt.Errorf("resolving subject manifest: %w", err)
	}
	subjDesc := subjMan.GetDescriptor()
	subjRef := r.SetDigest(subjDesc.Digest.String())

	// Store every envelope on its own so one failing does not stop the
	// rest. The failures are reported together in a StoreError.
	serr := repository.NewStoreError()
	for i, env := range envelopes {
		if err := c.storeEnvelope(ctx, rc, &subjRef, &subjDesc, env); err != nil {
			serr.Failed[i] = err
			continue
		}
		serr.Stored++
	}
	return serr.ErrorOrNil()
}

// storeEnvelope pushes a single envelope as a sigstore bundle referrer
// attached to subjRef.
func (c *Collector) storeEnvelope(
	ctx context.Context,
	rc *regclient.RegClient,
	subjRef *ref.Ref,
	subjDesc *descriptor.Descriptor,
	env attestation.Envelope,
) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshaling envelope: %w", err)
	}

	bundleDesc := descriptor.Descriptor{
		MediaType: sigstoreBundleArtifactType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	if _, err := rc.BlobPut(ctx, *subjRef, bundleDesc, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("pushing bundle blob: %w", err)
	}

	emptyData := []byte("{}")
	emptyDesc := descriptor.Descriptor{
		MediaType: ocispec.MediaTypeEmptyJSON,
		Digest:    digest.FromBytes(emptyData),
		Size:      int64(len(emptyData)),
	}
	if _, err := rc.BlobPut(ctx, *subjRef, emptyDesc, bytes.NewReader(emptyData)); err != nil {
		return fmt.Errorf("pushing empty config blob: %w", err)
	}

	m := &ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: sigstoreBundleArtifactType,
		Config: ocispec.Descriptor{
			MediaType: emptyDesc.MediaType,
			Digest:    emptyDesc.Digest,
			Size:      emptyDesc.Size,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: bundleDesc.MediaType,
			Digest:    bundleDesc.Digest,
			Size:      bundleDesc.Size,
		}},
		Subject: &ocispec.Descriptor{
			MediaType: subjDesc.MediaType,
			Digest:    subjDesc.Digest,
			Size:      subjDesc.Size,
		},
	}
	m.SchemaVersion = 2

	manData, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshaling referrer manifest: %w", err)
	}
	rcMan, err := manifest.New(manifest.WithRaw(manData))
	if err != nil {
		return fmt.Errorf("building referrer manifest: %w", err)
	}
	manRef := subjRef.SetDigest(digest.FromBytes(manData).String())
	if err := rc.ManifestPut(ctx, manRef, rcMan); err != nil {
		return fmt.Errorf("pushing referrer manifest: %w", err)
	}
	return nil
}

// fetchReferrer pulls the manifest for a single referrer descriptor and parses
// all of its layers as sigstore bundles.
func (c *Collector) fetchReferrer(
	ctx context.Context,
	rc *regclient.RegClient,
	subject *ref.Ref,
	desc *descriptor.Descriptor,
	opts *attestation.FetchOptions,
	parser *bundle.Parser,
) ([]attestation.Envelope, error) {
	// Build a reference to the referrer artifact by digest.
	rRef := subject.SetDigest(desc.Digest.String())

	m, err := rc.ManifestGet(ctx, rRef)
	if err != nil {
		return nil, fmt.Errorf("fetching referrer manifest: %w", err)
	}

	// Check if this referrer is a sigstore bundle. Some registries don't
	// propagate the manifest artifactType into the referrer descriptor, so
	// we check both the descriptor and the manifest itself.
	if !isSigstoreBundle(desc, m) {
		return nil, nil
	}

	mi, ok := m.(manifest.Imager)
	if !ok {
		return nil, fmt.Errorf("referrer manifest is not an image manifest")
	}

	layers, err := mi.GetLayers()
	if err != nil {
		return nil, fmt.Errorf("getting referrer layers: %w", err)
	}

	var atts []attestation.Envelope
	for j := range layers {
		blob, err := rc.BlobGet(ctx, rRef, layers[j])
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: pulling blob: %v", j, err)
			continue
		}

		data, err := io.ReadAll(readlimit.Reader(blob, opts.MaxReadSize))
		if err := blob.Close(); err != nil {
			logrus.Debugf("oci: closing blob %d: %v", j, err)
		}
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: reading blob: %v", j, err)
			continue
		}

		envs, err := parser.Parse(data)
		if err != nil {
			logrus.Debugf("oci: skipping layer %d: parsing bundle: %v", j, err)
			continue
		}
		if opts.KeepContent {
			envelope.KeepContent(envs, data)
		}

		atts = append(atts, envs...)
	}

	return atts, nil
}

// isSigstoreBundle returns true when the referrer looks like a sigstore bundle.
// It checks the descriptor-level artifactType first (which works on compliant
// registries) and falls back to inspecting the manifest's own artifactType and
// layer media types (needed for registries like GHCR that populate the
// descriptor artifactType from the config mediaType instead).
func isSigstoreBundle(desc *descriptor.Descriptor, m manifest.Manifest) bool {
	if desc.ArtifactType == sigstoreBundleArtifactType {
		return true
	}

	// Check layer media types as a fallback. When a registry does not
	// propagate artifactType correctly the layers still carry the bundle
	// media type.
	if mi, ok := m.(manifest.Imager); ok {
		if layers, err := mi.GetLayers(); err == nil {
			for i := range layers {
				if layers[i].MediaType == sigstoreBundleArtifactType {
					return true
				}
			}
		}
	}

	return false
}
