// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package coci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/hasher"
	"github.com/google/go-containerregistry/pkg/crane"
	ggcr "github.com/google/go-containerregistry/pkg/v1"
	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/envelope/bare"
	"github.com/policylabs/collector/internal/readlimit"
	"github.com/policylabs/collector/predicate/cyclonedx"
	"github.com/policylabs/collector/predicate/spdx"
	"github.com/policylabs/collector/predicate/spdx3"
	"github.com/policylabs/collector/statement/intoto"
)

// Media types of the layers cosign's legacy `attach sbom` layout can hold
// (from cosign's pkg/types). Only the JSON encodings have predicate parsers;
// the tag-value, XML and syft encodings are skipped.
const (
	spdxJSONMediaType      = "text/spdx+json"
	cycloneDXJSONMediaType = "application/vnd.cyclonedx+json"
)

// sbomLayerParsers maps an SBOM layer media type to the predicate parsers
// that can claim its contents, in the order they are tried. An SPDX layer
// may hold an SPDX 2 or an SPDX 3 document; each parser declines the other's.
var sbomLayerParsers = map[string][]attestation.PredicateParser{
	spdxJSONMediaType:      {spdx.New(), spdx3.New()},
	cycloneDXJSONMediaType: {cyclonedx.New()},
}

// fetchSBOMLayers reads the `.sbom` image that cosign's legacy `attach sbom`
// layout (still produced by ko) hangs off an image digest and wraps each SBOM
// layer into an in-toto statement about the image. The layout carries no
// signature, so the statements come back in bare envelopes that never verify.
// A missing `.sbom` tag is an empty result.
func (c *Collector) fetchSBOMLayers(ctx context.Context, opts attestation.FetchOptions, imageInfo *ImageInfo) ([]attestation.Envelope, error) {
	sbomRef := fmt.Sprintf(
		"%s/%s:%s.sbom",
		imageInfo.Registry, imageInfo.Repository,
		strings.Replace(imageInfo.Digest, "sha256:", "sha256-", 1),
	)

	manifestData, err := crane.Manifest(sbomRef, append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)...)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching .sbom manifest: %w", err)
	}

	manifest, err := ggcr.ParseManifest(bytes.NewReader(manifestData))
	if err != nil {
		return nil, fmt.Errorf("parsing .sbom manifest: %w", err)
	}

	subject, err := imageSubject(imageInfo)
	if err != nil {
		return nil, err
	}

	// An SBOM image holds a single layer in practice, so unlike the .att and
	// .sig paths the layers are pulled sequentially. Problems with one layer
	// are non-fatal.
	var atts []attestation.Envelope
	for i := range manifest.Layers {
		layer := &manifest.Layers[i]
		parsers, ok := sbomLayerParsers[string(layer.MediaType)]
		if !ok {
			logrus.Debugf("coci: skipping .sbom layer %d: unsupported media type %s", i, layer.MediaType)
			continue
		}
		env, err := c.getSBOMEnvelope(ctx, &opts, imageInfo, layer, parsers, subject, sbomRef)
		if err != nil {
			logrus.Debugf("coci: skipping .sbom layer %d: %v", i, err)
			continue
		}
		atts = append(atts, env)
		if opts.Limit > 0 && len(atts) >= opts.Limit {
			break
		}
	}

	return atts, nil
}

// getSBOMEnvelope pulls one SBOM layer, parses it with the first parser that
// claims it and returns it as an unsigned statement whose subject is the image.
func (c *Collector) getSBOMEnvelope(
	ctx context.Context, opts *attestation.FetchOptions, imageInfo *ImageInfo, layer *ggcr.Descriptor,
	parsers []attestation.PredicateParser, subject *gointoto.ResourceDescriptor, sbomRef string,
) (attestation.Envelope, error) {
	layerRef := imageInfo.Registry + "/" + imageInfo.Repository + "@" + layer.Digest.String()
	pulled, err := crane.PullLayer(layerRef, append([]crane.Option{crane.WithContext(ctx)}, c.craneOpts()...)...)
	if err != nil {
		return nil, fmt.Errorf("pulling SBOM layer: %w", err)
	}

	blob, err := pulled.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("reading SBOM blob: %w", err)
	}
	defer blob.Close() //nolint:errcheck

	data, err := io.ReadAll(readlimit.Reader(blob, opts.MaxReadSize))
	if err != nil {
		return nil, fmt.Errorf("reading SBOM data: %w", err)
	}

	pred, err := parseSBOM(data, parsers)
	if err != nil {
		return nil, err
	}

	hset, err := hasher.New().HashReaders([]io.Reader{bytes.NewReader(data)})
	if err != nil {
		return nil, fmt.Errorf("hashing SBOM data: %w", err)
	}
	origin := hset.ToResourceDescriptors()[0]
	origin.Uri = "oci:" + sbomRef
	if opts.KeepContent {
		origin.Content = data
	}
	pred.SetOrigin(origin)

	stmt := intoto.NewStatement(
		intoto.WithPredicate(pred),
		intoto.WithSubject(subject),
	)

	return &bare.Envelope{Statement: stmt}, nil
}

// parseSBOM returns the predicate of the first parser that claims the
// document. Parsers decline documents that are not theirs with
// attestation.ErrNotCorrectFormat; any other error is a broken document.
func parseSBOM(data []byte, parsers []attestation.PredicateParser) (attestation.Predicate, error) {
	for _, p := range parsers {
		pred, err := p.Parse(data)
		if err == nil {
			return pred, nil
		}
		if !errors.Is(err, attestation.ErrNotCorrectFormat) {
			return nil, fmt.Errorf("parsing SBOM: %w", err)
		}
	}
	return nil, errors.New("no predicate parser recognizes the SBOM document")
}

// imageSubject builds the in-toto subject describing the image that the
// statements synthesized from cosign's tag layout are about.
func imageSubject(imageInfo *ImageInfo) (*gointoto.ResourceDescriptor, error) {
	hexDigest, ok := strings.CutPrefix(imageInfo.Digest, "sha256:")
	if !ok {
		return nil, fmt.Errorf("unsupported digest format: %s", imageInfo.Digest)
	}
	return &gointoto.ResourceDescriptor{
		Name: imageInfo.Repository,
		Digest: map[string]string{
			"sha256": hexDigest,
		},
	}, nil
}
