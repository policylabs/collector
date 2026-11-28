// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package pypi

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gointoto "github.com/in-toto/attestation/go/v1"
	"github.com/policylabs/attestation"
	sapi "github.com/policylabs/signer/api/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/policylabs/collector/envelope"
)

const (
	wheelName   = "sampleproject-4.0.0-py3-none-any.whl"
	wheelSHA256 = "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b"
	sdistName   = "sampleproject-4.0.0.tar.gz"
	sdistSHA256 = "0ace7980f82c5815ede4cd7bf9f6693684cec2ae47b9b7ade9add533b8627c6b"
)

// newTestIndex serves the sampleproject 4.0.0 fixtures the way pypi.org
// does: the JSON API for the release listing and the integrity API for the
// per-file provenance. Anything else is a 404.
func newTestIndex(t *testing.T) *httptest.Server {
	t.Helper()
	serve := func(w http.ResponseWriter, name, contentType string) {
		data, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if _, err := w.Write(data); err != nil {
			t.Error(err)
		}
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/sampleproject/json":
			serve(w, "sampleproject-latest.json", "application/json")
		case "/pypi/sampleproject/4.0.0/json":
			serve(w, "sampleproject-4.0.0.json", "application/json")
		case "/integrity/sampleproject/4.0.0/" + wheelName + "/provenance":
			if r.Header.Get("Accept") != provenanceMediaType {
				w.WriteHeader(http.StatusNotAcceptable)
				return
			}
			serve(w, wheelName+".provenance.json", provenanceMediaType)
		case "/integrity/sampleproject/4.0.0/" + sdistName + "/provenance":
			serve(w, sdistName+".provenance.json", provenanceMediaType)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestNew(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		purl    string
		mustErr bool
		expect  string
	}{
		{"release", "pkg:pypi/sampleproject@4.0.0", false, "pkg:pypi/sampleproject@4.0.0"},
		{"latest", "pkg:pypi/sampleproject", false, "pkg:pypi/sampleproject"},
		{"file", "pkg:pypi/sampleproject@4.0.0?file_name=" + wheelName, false, "pkg:pypi/sampleproject@4.0.0?file_name=" + wheelName},
		{"normalized-name", "pkg:pypi/Sample_Project.Two@1.0", false, "pkg:pypi/sample-project-two@1.0"},
		{"global", "", false, ""},
		{"file-without-version", "pkg:pypi/sampleproject?file_name=" + wheelName, true, ""},
		{"wrong-type", "pkg:npm/sampleproject@4.0.0", true, ""},
		{"not-a-purl", "sampleproject", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithPackageURL(tc.purl))
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.expect == "" {
				require.False(t, c.Options.HasPackageURL())
				return
			}
			require.Equal(t, tc.expect, c.Options.PackageURL.String())
		})
	}
}

func TestNormalizeName(t *testing.T) {
	t.Parallel()
	for in, out := range map[string]string{
		"sampleproject":   "sampleproject",
		"Sample_Project":  "sample-project",
		"zope.interface":  "zope-interface",
		"Foo--Bar__baz.q": "foo-bar-baz-q",
	} {
		require.Equal(t, out, normalizeName(in))
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		name  string
		purl  string
		files []string
	}{
		{"release", "pkg:pypi/sampleproject@4.0.0", []string{wheelName, sdistName}},
		{"latest", "pkg:pypi/sampleproject", []string{wheelName, sdistName}},
		{"single-file", "pkg:pypi/sampleproject@4.0.0?file_name=" + sdistName, []string{sdistName}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithPackageURL(tc.purl), WithIndexURL(srv.URL))
			require.NoError(t, err)

			envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
			require.NoError(t, err)
			require.Len(t, envs, len(tc.files))

			for i, env := range envs {
				stmt := env.GetStatement()
				require.NotNil(t, stmt)
				require.Equal(t, PublishPredicateType, stmt.GetPredicateType())

				subjects := stmt.GetSubjects()
				require.Len(t, subjects, 1)
				require.Equal(t, tc.files[i], subjects[0].GetName())
				require.Equal(t, "pkg:pypi/sampleproject@4.0.0?file_name="+tc.files[i], subjects[0].GetUri())
				require.NotEmpty(t, subjects[0].GetDigest()["sha256"])
			}
		})
	}
}

func TestFetchLimit(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0"), WithIndexURL(srv.URL))
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{Limit: 1})
	require.NoError(t, err)
	require.Len(t, envs, 1)
}

func TestFetchGlobalMode(t *testing.T) {
	t.Parallel()
	c, err := New()
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Empty(t, envs)
	envs, err = c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{PublishPredicateType})
	require.NoError(t, err)
	require.Empty(t, envs)
}

func TestFetchErrors(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	t.Run("unknown-release", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithPackageURL("pkg:pypi/sampleproject@9.9.9"), WithIndexURL(srv.URL))
		require.NoError(t, err)
		_, err = c.Fetch(t.Context(), attestation.FetchOptions{})
		require.Error(t, err)
	})

	t.Run("file-without-provenance", func(t *testing.T) {
		t.Parallel()
		c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0?file_name=nope.whl"), WithIndexURL(srv.URL))
		require.NoError(t, err)
		envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
		require.NoError(t, err)
		require.Empty(t, envs)
	})

	t.Run("server-error", func(t *testing.T) {
		t.Parallel()
		broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(broken.Close)
		c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0"), WithIndexURL(broken.URL))
		require.NoError(t, err)
		_, err = c.Fetch(t.Context(), attestation.FetchOptions{})
		require.Error(t, err)
	})
}

func TestFetchBySubject(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		name     string
		purl     string
		subjects []attestation.Subject
		expect   []string
	}{
		{
			"configured-digest", "pkg:pypi/sampleproject@4.0.0",
			[]attestation.Subject{&gointoto.ResourceDescriptor{Digest: map[string]string{"sha256": sdistSHA256}}},
			[]string{sdistName},
		},
		{
			"configured-unknown-digest", "pkg:pypi/sampleproject@4.0.0",
			[]attestation.Subject{&gointoto.ResourceDescriptor{Digest: map[string]string{"sha256": strings.Repeat("0", 64)}}},
			nil,
		},
		{
			"global-purl-uri", "",
			[]attestation.Subject{&gointoto.ResourceDescriptor{Uri: "pkg:pypi/sampleproject@4.0.0"}},
			[]string{wheelName, sdistName},
		},
		{
			"global-purl-name-and-digest", "",
			[]attestation.Subject{&gointoto.ResourceDescriptor{
				Name:   "pkg:pypi/SampleProject@4.0.0",
				Digest: map[string]string{"sha256": wheelSHA256},
			}},
			[]string{wheelName},
		},
		{
			"global-file-purl", "",
			[]attestation.Subject{&gointoto.ResourceDescriptor{Uri: "pkg:pypi/sampleproject@4.0.0?file_name=" + wheelName}},
			[]string{wheelName},
		},
		{
			"global-unknown-package-skipped", "",
			[]attestation.Subject{
				&gointoto.ResourceDescriptor{Uri: "pkg:pypi/nothere@1.0.0"},
				&gointoto.ResourceDescriptor{Uri: "pkg:pypi/sampleproject@4.0.0?file_name=" + sdistName},
			},
			[]string{sdistName},
		},
		{
			"global-no-purl", "",
			[]attestation.Subject{&gointoto.ResourceDescriptor{Name: "file.txt", Digest: map[string]string{"sha256": wheelSHA256}}},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(WithPackageURL(tc.purl), WithIndexURL(srv.URL))
			require.NoError(t, err)

			envs, err := c.FetchBySubject(t.Context(), attestation.FetchOptions{}, tc.subjects)
			require.NoError(t, err)
			require.Len(t, envs, len(tc.expect))
			for i, env := range envs {
				require.Equal(t, tc.expect[i], env.GetStatement().GetSubjects()[0].GetName())
			}
		})
	}
}

func TestFetchByPredicateType(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0"), WithIndexURL(srv.URL))
	require.NoError(t, err)

	envs, err := c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{PublishPredicateType})
	require.NoError(t, err)
	require.Len(t, envs, 2)

	envs, err = c.FetchByPredicateType(t.Context(), attestation.FetchOptions{}, []attestation.PredicateType{"https://slsa.dev/provenance/v1"})
	require.NoError(t, err)
	require.Empty(t, envs)
}

// TestFetchVerify checks the reassembled bundle verifies through the
// regular bundle path (offline, against the embedded sigstore trust root)
// and that the synthesized predicate carries the data recovered from the
// provenance object.
func TestFetchVerify(t *testing.T) {
	t.Parallel()
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0?file_name="+wheelName), WithIndexURL(srv.URL))
	require.NoError(t, err)
	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	env := envs[0]

	require.NoError(t, env.Verify())
	v := env.GetVerification()
	require.NotNil(t, v)
	require.True(t, v.GetVerified())
	sv, ok := v.(*sapi.Verification)
	require.True(t, ok)
	ids := sv.GetSignature().GetIdentities()
	require.Len(t, ids, 1)
	require.Equal(t, "https://token.actions.githubusercontent.com", ids[0].GetSigstore().GetIssuer())
	require.Equal(t, "https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/heads/main", ids[0].GetSigstore().GetIdentity())

	pred := env.GetPredicate()
	require.NotNil(t, pred)
	require.Equal(t, PublishPredicateType, pred.GetType())

	var data map[string]Extension
	require.NoError(t, json.Unmarshal(pred.GetData(), &data))
	require.Len(t, data, 1)
	ext, ok := data[ExtensionKey]
	require.True(t, ok)

	var publisher map[string]any
	require.NoError(t, json.Unmarshal(ext.Publisher, &publisher))
	require.Equal(t, "GitHub", publisher["kind"])
	require.Equal(t, "pypa/sampleproject", publisher["repository"])
	require.Equal(t, "release.yml", publisher["workflow"])

	require.Equal(t, Distribution{
		Project: "sampleproject", Version: "4.0.0", Filename: wheelName, Index: srv.URL,
	}, ext.Distribution)

	require.NotNil(t, ext.Certificate)
	require.Equal(t, "https://github.com/pypa/sampleproject", ext.Certificate.SourceRepositoryURI)
	require.Equal(t, "621e4974ca25ce531773def586ba3ed8e736b3fc", ext.Certificate.SourceRepositoryDigest)
	require.Equal(t, "push", ext.Certificate.BuildTrigger)
	require.Equal(t, "https://github.com/pypa/sampleproject/actions/runs/11713038981/attempts/1", ext.Certificate.RunInvocationURI)
	require.Equal(t, "github-hosted", ext.Certificate.RunnerEnvironment)

	require.NotNil(t, ext.LoggedAt)
	require.Equal(t, int64(1730932628), ext.LoggedAt.Unix())
	require.Equal(t, int64(147137144), ext.LogIndex)

	// The serialized envelope is the original bundle: the signed payload
	// still carries the null predicate.
	raw, err := json.Marshal(env)
	require.NoError(t, err)
	var b struct {
		DSSE struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	require.NoError(t, json.Unmarshal(raw, &b))
	payload, err := base64.StdEncoding.DecodeString(b.DSSE.Payload)
	require.NoError(t, err)
	require.Contains(t, string(payload), `"predicate":null`)
	require.Equal(t, wheelSHA256, env.GetStatement().GetSubjects()[0].GetDigest()["sha256"])
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
	srv := newTestIndex(t)
	t.Cleanup(srv.Close)

	c, err := New(WithPackageURL("pkg:pypi/sampleproject@4.0.0?file_name="+sdistName), WithIndexURL(srv.URL))
	require.NoError(t, err)

	envs, err := c.Fetch(t.Context(), attestation.FetchOptions{})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	require.Nil(t, envelope.OriginContent(envs[0].GetPredicate()), "content is not kept unless asked")

	envs, err = c.Fetch(t.Context(), attestation.FetchOptions{KeepContent: true})
	require.NoError(t, err)
	require.Len(t, envs, 1)
	content := requireKeptContent(t, envs[0])

	origin := envs[0].GetPredicate().GetOrigin()
	require.Equal(t, sdistName, origin.GetName())
	require.Equal(t, "pkg:pypi/sampleproject@4.0.0?file_name="+sdistName, origin.GetUri())

	// What is kept is a sigstore bundle carrying the statement as it was
	// signed, with the material to verify it; not the synthesized statement.
	kept := &protobundle.Bundle{}
	require.NoError(t, protojson.Unmarshal(content, kept))
	require.NotNil(t, kept.GetVerificationMaterial().GetCertificate())
	require.NotEmpty(t, kept.GetVerificationMaterial().GetTlogEntries())
	require.NotEmpty(t, kept.GetDsseEnvelope().GetSignatures())
	require.NotContains(t, string(kept.GetDsseEnvelope().GetPayload()), ExtensionKey)
	require.Contains(t, string(envs[0].GetPredicate().GetData()), ExtensionKey)
}
