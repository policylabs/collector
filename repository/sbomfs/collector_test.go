// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package sbomfs

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/mod"
	"github.com/protobom/protobom/pkg/native"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/envelope"
)

// dsse is a minimal DSSE envelope for testing.
type dsse struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// testStatement creates a minimal in-toto statement JSON for testing.
func testStatement(t *testing.T, predicateType string) []byte {
	t.Helper()
	stmt := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []interface{}{},
		"predicate":     map[string]interface{}{},
	}
	data, err := json.Marshal(stmt)
	require.NoError(t, err)
	return data
}

// testDSSE wraps a statement in a DSSE envelope.
func testDSSE(t *testing.T, predicateType string) []byte {
	t.Helper()
	payload := testStatement(t, predicateType)
	env := dsse{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []struct {
			Sig string `json:"sig"`
		}{{Sig: "dGVzdA=="}},
	}
	data, err := json.Marshal(env)
	require.NoError(t, err)
	return data
}

// writeSBOMWithAttestations creates a temporary SPDX SBOM file with attestation
// properties embedded as sbomfs entries on the root node.
func writeSBOMWithAttestations(t *testing.T, attestations map[string][]byte) string {
	t.Helper()

	node := &sbom.Node{
		Id:         "SPDXRef-Package",
		Name:       "test-package",
		Version:    "1.0.0",
		Properties: []*sbom.Property{},
	}

	for name, data := range attestations {
		node.Properties = append(node.Properties, &sbom.Property{
			Name: "sbomfs:" + name,
			Data: base64.StdEncoding.EncodeToString(data),
		})
	}

	doc := &sbom.Document{
		Metadata: &sbom.Metadata{
			Id:      "https://spdx.org/spdxdocs/test",
			Name:    "test-sbom",
			Version: "SPDX-2.3",
		},
		NodeList: &sbom.NodeList{
			Nodes:        []*sbom.Node{node},
			RootElements: []string{"SPDXRef-Package"},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.spdx.json")

	w := writer.New(
		writer.WithFormat(formats.SPDX23JSON),
		writer.WithSerializeOptions(&native.SerializeOptions{
			Mods: map[mod.Mod]struct{}{
				mod.SPDX_RENDER_PROPERTIES_IN_ANNOTATIONS: {},
			},
		}),
	)
	require.NoError(t, w.WriteFile(doc, path))

	return path
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("valid sbom", func(t *testing.T) {
		t.Parallel()
		path := writeSBOMWithAttestations(t, nil)
		c, err := New(WithPath(path))
		require.NoError(t, err)
		require.NotNil(t, c)
		require.NotNil(t, c.doc)
		require.NotNil(t, c.fs)
	})

	t.Run("missing path", func(t *testing.T) {
		t.Parallel()
		_, err := New()
		require.Error(t, err)
	})

	t.Run("invalid sbom path", func(t *testing.T) {
		t.Parallel()
		_, err := New(WithPath("/nonexistent/path.json"))
		require.Error(t, err)
	})
}

func TestFetch(t *testing.T) {
	t.Parallel()

	att := testDSSE(t, "https://slsa.dev/provenance/v0.2")

	path := writeSBOMWithAttestations(t, map[string][]byte{
		"attestation-0000.json": att,
	})

	c, err := New(WithPath(path))
	require.NoError(t, err)

	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestFetchEmpty(t *testing.T) {
	t.Parallel()

	path := writeSBOMWithAttestations(t, nil)

	c, err := New(WithPath(path))
	require.NoError(t, err)

	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestStore(t *testing.T) {
	t.Parallel()

	// Create an SBOM with no attestations.
	path := writeSBOMWithAttestations(t, nil)

	c, err := New(WithPath(path))
	require.NoError(t, err)

	// Create a minimal envelope to store. We'll marshal a DSSE envelope
	// and then parse it to get a proper attestation.Envelope.
	att := testDSSE(t, "https://slsa.dev/provenance/v0.2")

	// First, write the attestation data as a file in the sbomfs to parse it.
	require.NoError(t, c.fs.WriteFile("bootstrap.json", att))

	// Now fetch it back as a proper envelope.
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)

	// Remove the bootstrap file.
	require.NoError(t, c.fs.RemoveFile("bootstrap.json"))

	// Store the envelope through the Store interface.
	err = c.Store(t.Context(), attestation.StoreOptions{}, envs)
	require.NoError(t, err)

	// Verify the SBOM file was updated by reading it fresh.
	c2, err := New(WithPath(path))
	require.NoError(t, err)

	envs2, err := c2.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs2, 1)
}

func TestStoreMultiple(t *testing.T) {
	t.Parallel()

	att1 := testDSSE(t, "https://slsa.dev/provenance/v0.2")
	att2 := testDSSE(t, "https://in-toto.io/attestation/vulns/v0.1")

	path := writeSBOMWithAttestations(t, map[string][]byte{
		"existing.json": att1,
	})

	c, err := New(WithPath(path))
	require.NoError(t, err)

	// Parse the second attestation by writing and reading it.
	require.NoError(t, c.fs.WriteFile("temp.json", att2))
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 2)

	// Remove temp and keep only existing.
	require.NoError(t, c.fs.RemoveFile("temp.json"))

	// Store both attestations, the index should start at 1 (existing.json counts).
	err = c.Store(t.Context(), attestation.StoreOptions{}, envs)
	require.NoError(t, err)

	// Read fresh and verify we have the original + 2 new stored ones.
	c2, err := New(WithPath(path))
	require.NoError(t, err)

	envs2, err := c2.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	// existing.json + 2 stored attestations = 3
	require.Len(t, envs2, 3)
}

func TestBuild(t *testing.T) {
	t.Parallel()

	path := writeSBOMWithAttestations(t, nil)
	repo, err := Build(path)
	require.NoError(t, err)
	require.NotNil(t, repo)
}

func TestOriginalFormatPreserved(t *testing.T) {
	t.Parallel()

	path := writeSBOMWithAttestations(t, nil)

	c, err := New(WithPath(path))
	require.NoError(t, err)

	// Store an empty set to trigger a write-back.
	require.NoError(t, c.Store(t.Context(), attestation.StoreOptions{}, nil))

	// Verify the file is still valid SPDX JSON.
	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Contains(t, raw, "spdxVersion")
}

func TestSanitizePredicateType(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input, expected string
	}{
		{"https://slsa.dev/provenance/v0.2", "v0.2"},
		{"https://in-toto.io/attestation/vulns/v0.1", "v0.1"},
		{"simple", "simple"},
	} {
		result := sanitizePredicateType(tc.input)
		require.Equal(t, tc.expected, result, "sanitizePredicateType(%q)", tc.input)
	}
}

// requireKeptContent checks that an attestation kept content that hashes to
// the digest of its origin and returns it.
func requireKeptContent(t *testing.T, env attestation.Envelope) []byte {
	t.Helper()
	content := envelope.OriginContent(env.GetPredicate())
	require.NotEmpty(t, content)
	sum := sha256.Sum256(content)
	require.Equal(t, hex.EncodeToString(sum[:]), env.GetPredicate().GetOrigin().GetDigest()["sha256"])
	return content
}

func TestFetchKeepContent(t *testing.T) {
	t.Parallel()

	att := testDSSE(t, "https://slsa.dev/provenance/v0.2")
	path := writeSBOMWithAttestations(t, map[string][]byte{
		"attestation-0000.json": att,
	})
	c, err := New(WithPath(path))
	require.NoError(t, err)

	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.Nil(t, envelope.OriginContent(envs[0].GetPredicate()), "content is not kept unless asked")

	envs, err = c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.Equal(t, att, requireKeptContent(t, envs[0]))
}
