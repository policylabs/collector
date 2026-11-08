# Repository Collectors

The collector agent fetches attestations from a variety of sources through
repository collector drivers. Each driver implements one or more of the
`attestation.Fetcher`, `attestation.FetcherBySubject`, and
`attestation.FetcherByPredicateType` interfaces.

## filesystem (`fs`)

Walks a local or embedded `fs.FS` filesystem and parses any files with
recognized extensions (`.json`, `.jsonl`, `.spdx`, `.cdx`, `.bundle`,
`.hjson`). JSONL files are parsed as multi-attestation bundles; all other
files are passed to the standard envelope parsers. `WithExtensions` replaces
the list (`DefaultExtensions` holds the default one).

## git

Clones a git repository into memory at the locator's ref and reads
attestations from the checkout through the **filesystem** collector
(`WithExtensions` is passed through to it). The ref after `@` may be a full
reference name, a short tag or branch name (resolved against the remote,
tags first), or a commit sha (fetched alone where the remote serves
commits by id, as GitHub does; otherwise the history is cloned and the
commit checked out). Without a ref the remote's HEAD is cloned shallow.

The driver also describes the git object the locator lands on, as
attestations synthesized by the [`gitobject` library](git-objects.md): the
checked-out commit always (`https://carabiner.dev/git/commit/v0`, subjects
the commit and its tree) and the tag when the ref is an annotated tag
(`https://carabiner.dev/git/tag/v0`, subjects the tag object and its
target). Their verification is the object's PGP signature, checked against
the keys set with `SetKeys` and GitHub's web-flow key.

A subject query naming a commit the checkout does not describe fetches
that commit alone (or, where the remote does not serve commits by id,
clones the history and finds it) and describes it the same way, once per
sha. A chain that lands on a commit no branch reaches any more, a pull
request's head after a squash, thus still finds the commit described
without anyone naming it up front. A policy can chain from a release tag
to its commit to its tree, or to the evaluated head, with every hop proven
by git itself.

## github

Fetches attestations from the GitHub Attestations API. Only supports
fetching by subject (digest). Attestations are returned as Sigstore
bundles. Also supports storing attestations via the upload endpoint.

## http / https

A general-purpose HTTP collector that fetches attestation data from one or
more URLs. Supports Go `text/template` URL patterns for subject name,
subject digest, subject URI, and predicate type, enabling the collector to
construct URLs dynamically. Responses are parsed as JSONL by default.

Depending on the configured URL templates, `New()` returns one of several
collector variants that implement different combinations of the fetcher
interfaces.

## jsonl

Reads attestations from local JSON Lines (`.jsonl`) files. Each line in the
file is an independent attestation envelope. Supports parallel parsing of
multiple files.

## note

Reads attestations stored in git commit notes. Clones the remote notes ref
and extracts JSONL-formatted attestation bundles from the note associated
with a specific commit SHA. Also supports storing attestations by pushing
notes back to the remote.

## dnote (Dynamic Git Notes)

A dynamic variant of the **note** collector. Instead of being preconfigured to
read from a specific commit, the dynamic notes collector creates a fixed notes
collector on the fly for each subject it encounters. When `FetchBySubject` is
called, it inspects the subjects for SHA-1 or `gitCommit` digests and
automatically constructs a notes collector targeting each commit. This makes it
suitable for scenarios where the set of commits is not known in advance.

Also supports storing attestations. When `Store` is called, the collector
inspects all envelope subjects looking for SHA-1 or `gitCommit` digests, groups
the envelopes by commit, and creates a notes collector per commit to write
them. All envelopes are validated before any writes occur — if any envelope
lacks a SHA-1 or `gitCommit` subject, an error is returned.

## coci (Container OCI)

Reads and writes attestations attached to OCI container images using the
legacy cosign tag convention (`<repo>:sha256-<digest>.att`). On read, the
`.att` manifest is fetched, each DSSE envelope layer is pulled, and a
Sigstore bundle is synthesized from the layer body plus its cosign
annotations (certificates, transparency log entries, RFC 3161 timestamps).

The same read also covers the two other tags cosign's legacy layout hangs
off an image digest. `.sig` holds signatures, which come back as
`https://cosign.sigstore.dev/signature/v1` attestations. `.sbom` is the
deprecated `cosign attach sbom` layout (still produced by ko): layers with
media type `text/spdx+json` or `application/vnd.cyclonedx+json` are parsed
with the SPDX 2/3 and CycloneDX predicate parsers and returned as
**unsigned** in-toto statements in bare envelopes, with the image digest as
the subject. They never verify and carry no signer identity. Other SBOM
encodings (tag-value, XML, syft) are skipped. Problems reading the `.sig` or
`.sbom` images are logged and do not fail the fetch; a missing tag is an
empty result. Each of the three tags can be switched off with
`WithReadAttestations(false)`, `WithReadSignatures(false)` and
`WithReadSBOMs(false)`; all are read by default.

When `Store` is called the inverse path runs:

1. The reference is resolved to its image digest so the `.att` tag can be
   computed.
2. The existing `.att` manifest (if any) is pulled so its layers are
   preserved; new attestations are appended (cosign-style append-on-write).
   A missing tag is treated as "no attestations yet" and a fresh empty
   image is used as the base.
3. Each envelope is converted to a DSSE layer with media type
   `application/vnd.dsse.envelope.v1+json`. `*bundle.Envelope` inputs are
   unwrapped: the DSSE payload becomes the layer body and any sigstore
   verification material is hoisted back into cosign layer annotations
   (`dev.sigstore.cosign/certificate`, `dev.sigstore.cosign/bundle`,
   `dev.sigstore.cosign/rfc3161timestamp`) so the result round-trips with
   both this collector's `Fetch` and with cosign itself. Each layer also
   gets the `predicateType` annotation `cosign attest` writes, set to the
   predicate type of the in-toto statement in the layer.
4. The resulting OCI image manifest is pushed at the `.att` tag.

Authentication uses the standard Docker keychain
(`~/.docker/config.json`, `$DOCKER_CONFIG`, configured credential helpers).
Tests and other callers can override registry options via `WithCraneOpts`
(e.g. `crane.Insecure` for an HTTP test registry). The implementation is
built directly on
[`go-containerregistry`](https://github.com/google/go-containerregistry);
it does not depend on `cosign`.

## oci (OCI Referrers)

Reads and writes Sigstore bundle attestations attached as OCI referrers.
Cosign v3 attaches signatures and attestations as OCI artifacts that
reference the subject image via the OCI Referrers API, rather than using
the `.att`/`.sig` tag convention used by the **coci** collector.

The collector queries the Referrers API for artifacts with artifact type
`application/vnd.dev.sigstore.bundle.v0.3+json`, pulls their blob layers,
and parses each as a Sigstore bundle using the standard `bundle.Parser`.

Init string format: `oci:<image-ref>` (e.g. `oci:ghcr.io/foo/bar:v1` or
`oci:ghcr.io/foo/bar@sha256:abc...`). Tag references are automatically
resolved to digests before querying referrers.

Authentication uses the Docker credential chain (`~/.docker/config.json`,
`$DOCKER_CONFIG`, `$DOCKER_AUTH_CONFIG`, and configured credential helpers)
and Docker CA certificates (`/etc/docker/certs.d`). Callers can override
this with `WithRegClientOpts` to inject custom registry hosts or transport
options.

When `Store` is called, each envelope is JSON-marshaled (the envelope is
expected to be a Sigstore bundle, e.g. `*bundle.Envelope`) and uploaded as
a new referrer pointing at the subject image:

1. The subject reference is resolved via `ManifestHead` to capture its
   digest, size, and media type.
2. The bundle bytes are pushed as a blob with media type
   `application/vnd.dev.sigstore.bundle.v0.3+json`.
3. An empty `{}` config blob with media type
   `application/vnd.oci.empty.v1+json` is pushed.
4. An OCI image manifest is built with `artifactType` set to the Sigstore
   bundle media type, the bundle blob as its single layer, and `subject`
   pointing at the resolved image digest. The manifest is pushed at its
   own content-addressable digest so the registry exposes it through the
   Referrers API.

The implementation is built directly on
[`regclient`](https://github.com/regclient/regclient); it does not depend
on `cosign`.

## release

Reads attestations from GitHub release assets. Constructs a virtual
filesystem from the release's downloadable assets and delegates to the
**filesystem** collector to parse them. Only assets with the attestation
extensions (the **filesystem** defaults, or the list given to
`WithExtensions`) and their signature, certificate and key sidecars are
downloaded.

For [immutable releases](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/)
the collector also returns the release attestation GitHub generates
(predicate type `https://in-toto.io/attestation/release/v0.2`). That
attestation is not a release asset: GitHub keeps it in the repository's
attestation store, keyed by the digest of the release tag reference, so the
collector resolves the tag and reads it from there, the same lookup
`gh release verify` performs. Releases that are not immutable have no such
attestation and only their assets are read.

Also supports storing attestations. When `Store` is called, each envelope is
JSON-marshaled and uploaded to the release as an individual, content-addressed
asset named `attestation-<sha256>.json`. Uploads are retried with exponential
backoff (see `WithRetries`) and an asset that already exists on the release is
left in place, making `Store` idempotent. A token is required for uploads (and
for reading private releases); set it with `WithToken` or via the
`GITHUB_TOKEN` / `GH_TOKEN` environment variables.

## actions

Reads attestations from the artifacts of a GitHub Actions workflow run. Runs
are addressed with a locator of the form
`actions://<host>/<owner>/<repo>/run/<run-id>`, for example
`actions://github.com/carabiner-labs/baseline-init/run/34180821665`. The host
may be github.com, a GitHub Enterprise Cloud data residency host (`*.ghe.com`)
or a GitHub Enterprise Server; the REST API location is derived from it. The
`run` segment is fixed so other things can be addressed later.

Only the artifacts whose name carries one of the configured extensions are
downloaded (by default the **filesystem** collector's extensions plus `zip`)
and expired artifacts are skipped. GitHub delivers every artifact as a zip
archive, which is handed to the **filesystem** collector, so bare statements,
DSSE envelopes, Sigstore bundles, JSONL files and sidecar signatures are all
supported. Zip files found inside an artifact are expanded and scanned with
the same extensions. `WithExtensions` changes the list.

Workflow run artifacts cannot be downloaded anonymously, so a token is always
required. Set it with `WithToken` or via the `GITHUB_TOKEN` / `GH_TOKEN`
environment variables; a workflow's own token can read the artifacts of its
run. The token is only sent to the API host, never to the storage host the
downloads redirect to. Storing is not supported as GitHub offers no API to add
artifacts to a run.

## maven

Reads attestations published alongside an artifact in a Maven repository.
The init string is the `maven:` moniker followed by a Maven package URL
(purl) with namespace, name and version, for example
`maven:pkg:maven/org.apache.commons/commons-lang3@3.21.0-SNAPSHOT`. The purl
maps to the artifact's version directory under the repository base URL
(`<base>/org/apache/commons/commons-lang3/3.21.0-SNAPSHOT/`). The base URL
defaults to Maven Central and can be changed with `WithBaseURL` or with a
`repository_url` qualifier on the purl.

The collector reads the directory's `maven-metadata.xml` and resolves every
file through its `snapshotVersions` entries, the layout Maven writes for
SNAPSHOT deployments, so it needs that metadata to be present. Three kinds of
files are collected from it:

- **JSONL attestation bundles** (`<artifact>-<version>.intoto.jsonl`), parsed
  as any other JSONL file.
- **Unsigned SBOMs**: SPDX (`.spdx.json`) and CycloneDX (`.cdx.json`, or a
  `.json` file with the `cyclonedx` classifier), returned as unsigned
  statements.
- **PGP-signed artifacts**: when the artifact and its `.asc` signature are
  both listed at the same snapshot version, the artifact is downloaded and
  the signature checked against the public keys registered on the collector
  (see [virtual attestations](virtual-attestations.md)). A verified signature
  yields a virtual attestation with the artifact's digest as its subject; no
  keys or a signature that no key verifies yields nothing. The artifact is
  selected by the purl's `type` qualifier (default `jar`) and `classifier`
  qualifier.

With an empty init string (`maven:`) the collector runs in global mode and
resolves purls from the subjects handed to `FetchBySubject` (from their URI or
name fields), reading each one from its own `repository_url` qualifier or the
configured base URL. In either mode `FetchBySubject` returns only the
attestations whose subject digests match those of the requested subjects.
Storing is not supported.

## ossrebuild

Fetches rebuild attestations from the Google OSS Rebuild project. Converts
package URLs (purls) in the subject URI into storage URLs and delegates to
the **http** collector to fetch the JSONL data.

## pypi

Reads [PEP 740](https://peps.python.org/pep-0740/) attestations from a Python
package index. The init string is the `pypi:` moniker followed by a PyPI
package URL (purl), which selects what to read:

| Init string | Reads |
| --- | --- |
| `pypi:pkg:pypi/sampleproject@4.0.0` | every distribution file of the release |
| `pypi:pkg:pypi/sampleproject` | every file of the latest release |
| `pypi:pkg:pypi/sampleproject@4.0.0?file_name=sampleproject-4.0.0.tar.gz` | a single wheel or sdist |
| `pypi:` | global mode (see below) |

Project names are normalized as described in PEP 503, so `Sample_Project` and
`sample-project` address the same project. With an empty init string
(`pypi:`) the collector runs in global mode and resolves purls from the
subjects handed to `FetchBySubject` (from their URI or name fields), so a
subject with `pkg:pypi/sampleproject@4.0.0` as its URI is enough to find its
attestations. `WithIndexURL` points the collector at
another index; both the JSON API (`/pypi/<project>/<version>/json`, used to
list a release's files) and the integrity API
(`/integrity/<project>/<version>/<file>/provenance`) must be served under it.

For each file the collector reads the provenance object and returns every
attestation of every attestation bundle in it. Each one is reassembled into a
sigstore bundle (the DSSE envelope, the Fulcio signing certificate and the
Rekor transparency log entries) so it verifies offline through the regular
bundle path. Files that have no provenance are skipped.

PyPI's publish attestation (predicate type
`https://docs.pypi.org/attestations/publish/v1`) has a null predicate by
specification: on its own it asserts nothing beyond the subject and the signer
identity. The collector keeps the predicate type but serves a synthesized
predicate whose only key is `_policylabs`. The leading underscore marks the
contents as a collector extension, not part of the PyPI specification, and
keeps the key a valid CEL identifier (`predicate._policylabs.publisher`).
Under it are
`publisher` (the index's trusted publisher record, verbatim), `distribution`
(project, version, filename, packageType, url, index), `certificate` (a summary
of the Fulcio signing certificate: certificateIssuer, subjectAlternativeName,
issuer, sourceRepositoryURI, sourceRepositoryDigest, sourceRepositoryRef,
buildConfigURI, buildTrigger, runInvocationURI, runnerEnvironment and the
other build extensions), `loggedAt` (the Rekor integrated time) and
`logIndex`. Abbreviated:

```json
{
  "_policylabs": {
    "publisher": {
      "kind": "GitHub",
      "repository": "pypa/sampleproject",
      "workflow": "release.yml"
    },
    "distribution": {
      "project": "sampleproject",
      "version": "4.0.0",
      "filename": "sampleproject-4.0.0-py3-none-any.whl"
    },
    "certificate": {
      "issuer": "https://token.actions.githubusercontent.com",
      "subjectAlternativeName": "https://github.com/pypa/sampleproject/.github/workflows/release.yml@refs/heads/main",
      "sourceRepositoryDigest": "621e4974ca25ce531773def586ba3ed8e736b3fc",
      "buildTrigger": "push",
      "runInvocationURI": "https://github.com/pypa/sampleproject/actions/runs/11713038981/attempts/1"
    },
    "loggedAt": "2024-11-06T22:37:08Z",
    "logIndex": 147137144
  }
}
```

The signed payload is not modified: verification runs over the original bytes
and the signer identity lands in the verification result as with any other
bundle. Attestations whose statement carries a real predicate (PyPI also
accepts SLSA provenance v1) are served exactly as signed. Storing is not
supported.
