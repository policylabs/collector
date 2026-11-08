# Attestations from Git Objects

The `gitobject` package synthesizes attestations from git objects: a commit
or an annotated tag becomes an in-toto statement whose predicate is the
object's content and whose subjects are what the object's bytes prove.
Nothing is stored and nothing is signed. The envelope is virtual; what
vouches for the statement is the object's own signature, carried as the
predicate's verification when a known key verifies it.

The package is a library, not a driver. Any git-related driver that wants to
describe the objects it reads uses it, so a verifier sees the same commit and
tag attestations whichever driver served them.

## Predicates

Two predicate types, defined in `predicate/git`:

| Type | Content |
|---|---|
| `https://carabiner.dev/git/commit/v0` | `tree`, `parents`, `author`, `committer`, `message`, `trailers` |
| `https://carabiner.dev/git/tag/v0` | `object`, `objectType`, `name`, `tagger`, `message`, `trailers` |

They say what the object stores and nothing else; in particular nothing
about who signed it, which is the verification's job. They are deliberately
not gitsign's types: a gitsign predicate states that gitsign signed the
object, these state what the object contains, signed or not, by anyone.

`trailers` are the message's trailers as git defines them: the last
paragraph, when every line in it is `Token: value` or a continuation line,
and it is not the only paragraph. They are a map from token to the list of
its values in message order. The parser attaches no meaning to any token.
What `Evaluated-Commit` or `Signed-off-by` means is for whoever wrote the
trailer and for the policy that reads it, so a policy chains through them
with `predicate.data.trailers["Evaluated-Commit"][0]`.

## Subjects

A commit attestation has two subjects: the commit, with `sha1` and
`gitCommit` digests and the remote's URL as its name, and its tree, with a
`gitTree` digest only. The commit's bytes hash to the first and name the
second, so both are proven by the object. A tag attestation likewise names
the tag object (`sha1`, `gitTag`) and its target (`sha1` plus the digest
named after the target's type, `gitCommit` for a commit).

That is what lets a policy walk a chain of objects: a release tag to the
commit it points at, that commit to its tree, a trailer to another commit,
that commit to the same tree. Each hop is an attestation whose subject is
proven by git itself.

## Verification

The attestation's verification is the object's own signature, checked by
the library and reported as the signer's identity:

- a **sigstore signature**, the CMS that gitsign writes, is verified the way
  the gitsign driver verifies it, with the same code: the signature over
  the object's bytes, the leaf certificate's chain to Fulcio, and the Rekor
  transparency log entry, embedded (offline mode) or looked up (online
  mode), against the trust root the signer library ships. The identity is
  the certificate's issuer and subject.
- a **PGP signature** is verified against the keys the verifier is given
  (`WithKeys`, `SetKeys`) and the keys the package ships with, today
  GitHub's web-flow key (`keys/github-web-flow.asc`, from
  <https://github.com/web-flow.gpg>), so a merge or squash commit GitHub made
  verifies as GitHub's with no configuration. The identity is the key.

An unsigned object, an SSH-signed one or a signature that does not verify
yields an attestation with no verification: "nothing established", never
"forged". The policy decides what an unverified object is worth.

The gitsign driver uses this same verifier for the gitsign attestations it
synthesizes, so the two drivers never disagree about a signature. They
differ in what they describe: gitsign's attestation states that gitsign
signed the object, the git driver's states what the object contains.

## Use

```go
s := gitobject.New(gitobject.WithRemote("origin"), gitobject.WithKeys(keys...))
env, err := s.Commit(ctx, repo, plumbing.NewHash(sha))      // commit attestation
env, err := s.Tag(ctx, repo, tagObjectHash)                  // tag attestation
env, err := s.TagNamed(ctx, repo, "v1.2.0")                  // by name; lightweight tags are ErrLightweightTag
```

`repo` is a go-git repository the caller opened; how it was fetched (a
clone, a single ref such as `refs/pull/N/head`) is the driver's business.
