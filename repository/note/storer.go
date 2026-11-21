// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package note

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/carabiner-dev/vcslocator"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/policylabs/attestation"
	"github.com/sirupsen/logrus"

	"github.com/policylabs/collector/repository"
)

var _ attestation.Storer = (*Collector)(nil)

const (
	notesRef = "refs/notes/commits"
)

// Store implements the attestation.Storer interface
func (c *Collector) Store(ctx context.Context, opts attestation.StoreOptions, envelopes []attestation.Envelope) error {
	if c.Options.Locator == "" {
		return errors.New("unable to write note, no VCS locator set")
	}

	components, err := vcslocator.Locator(c.Options.Locator).Parse()
	if err != nil {
		return fmt.Errorf("parsing VCS locator: %w", err)
	}

	if components.Commit == "" {
		return fmt.Errorf("VCS locator must specify a commit sha")
	}

	// Determine if we should push based on transport type
	// Default to pushing for remote repos, not pushing for local file:// repos
	shouldPush := components.Transport != vcslocator.TransportFile
	if c.Options.Push != nil {
		shouldPush = *c.Options.Push
	}

	// Open or clone the repository
	repo, err := c.openOrCloneRepoForNotes(ctx, components)
	if err != nil {
		return fmt.Errorf("opening repository: %w", err)
	}

	// A clone is this call's own copy of the remote: a rejected push can be
	// tried again on what the remote has by then. A local repository is the
	// caller's, and its notes are not ours to reset.
	isClone := components.Transport != vcslocator.TransportFile
	return c.storeInRepo(ctx, repo, components.Commit, envelopes, shouldPush, isClone)
}

// maxPushAttempts is how many times a note is pushed before giving up.
const maxPushAttempts = 3

// pushRetryDelay is waited before the second push, and twice that before
// the third. A variable so tests do not wait.
var pushRetryDelay = time.Second

// storeInRepo writes the envelopes to the commit's note in repo and, when
// asked, pushes the notes ref.
//
// A push is rejected when the remote's notes moved after they were read:
// every note of a repository lives under the one ref, so two writers, or one
// writer storing two notes in a row, race for it. With retry, a rejected
// push is tried again from the start: the remote's notes are fetched as they
// are now, the note is written on top of them, and that is pushed. Nothing
// already in the notes is lost, and the envelopes are written once.
func (c *Collector) storeInRepo(
	ctx context.Context, repo *git.Repository, commit string,
	envelopes []attestation.Envelope, push, retry bool,
) error {
	for attempt := 1; ; attempt++ {
		serr, err := c.writeNote(repo, commit, envelopes)
		if err != nil {
			return err
		}
		if !push {
			return serr.ErrorOrNil()
		}

		err = c.pushNotes(ctx, repo)
		if err == nil {
			return serr.ErrorOrNil()
		}
		if !retry || attempt >= maxPushAttempts || !retryablePush(ctx, err) {
			return fmt.Errorf("pushing notes: %w", err)
		}
		logrus.Debugf("note: push %d of %d for commit %s was rejected, trying again: %v",
			attempt, maxPushAttempts, commit, err)

		select {
		case <-ctx.Done():
			return fmt.Errorf("pushing notes: %w", ctx.Err())
		case <-time.After(time.Duration(attempt) * pushRetryDelay):
		}
		if err := c.resetNotesToRemote(ctx, repo); err != nil {
			return fmt.Errorf("pushing notes: reading the remote's notes after a rejected push: %w", err)
		}
	}
}

// retryablePush reports whether a failed push is worth another attempt. A
// push that failed for lack of access will fail again, and so will any
// under a context that is done; the rest (the ref moved, the remote could
// not take the pack, the connection dropped) may well not.
func retryablePush(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	for _, permanent := range []error{
		transport.ErrAuthenticationRequired,
		transport.ErrAuthorizationFailed,
		transport.ErrRepositoryNotFound,
		transport.ErrInvalidAuthMethod,
	} {
		if errors.Is(err, permanent) {
			return false
		}
	}
	return true
}

// writeNote adds the envelopes to the commit's note in the repository's
// notes ref, on top of whatever the ref holds. The envelopes that could not
// be serialized are reported in the returned StoreError, which is nil when
// there were none.
func (c *Collector) writeNote(
	repo *git.Repository, commit string, envelopes []attestation.Envelope,
) (*repository.StoreError, error) {
	// Read existing bundle if it exists
	existingData, notePath, isSharded, err := c.readExistingBundle(repo, commit)
	if err != nil {
		return nil, fmt.Errorf("reading existing bundle: %w", err)
	}

	// Validate existing data is JSONL if present
	if len(existingData) > 0 {
		if err := c.validateJSONL(existingData); err != nil {
			return nil, fmt.Errorf("existing note data is not valid JSONL: %w", err)
		}
	}

	// Serialize new attestations to JSONL. Envelopes that cannot be
	// serialized are skipped and reported once the rest is written.
	newJSONL, serr := c.serializeToJSONL(envelopes)
	if len(envelopes) > 0 && serr.AllFailed() {
		return nil, serr
	}

	// Append new JSONL to existing data
	jsonlData := existingData
	if len(existingData) > 0 && !bytes.HasSuffix(existingData, []byte("\n")) {
		// Ensure existing data ends with newline before appending
		jsonlData = append(jsonlData, '\n')
	}
	jsonlData = append(jsonlData, newJSONL...)

	// Check if we need to shard based on the existing structure or repository state
	shouldShard := isSharded || c.shouldShardNotes(repo)
	finalPath := notePath
	if shouldShard && !isSharded {
		// Transition from non-sharded to sharded
		finalPath = commit[0:2] + "/" + commit[2:]
	}

	// Update the notes ref with the new data
	if err := c.updateNotesRef(repo, finalPath, jsonlData, commit); err != nil {
		return nil, fmt.Errorf("updating notes ref: %w", err)
	}
	return serr, nil
}

// resetNotesToRemote makes the local notes ref the remote's again, dropping
// the commit a rejected push left on it. When the remote has no notes, the
// local ref is removed, so the next write starts them.
func (c *Collector) resetNotesToRemote(ctx context.Context, repo *git.Repository) error {
	auth, err := vcslocator.GetAuthMethod(
		c.Options.Locator, vcslocator.WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
	)
	if err != nil {
		return fmt.Errorf("getting auth method: %w", err)
	}
	err = repo.FetchContext(ctx, &git.FetchOptions{
		Auth:  auth,
		Force: true,
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("+%s:%s", notesRef, notesRef)),
		},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, git.NoMatchingRefSpecError{}):
		if err := repo.Storer.RemoveReference(plumbing.ReferenceName(notesRef)); err != nil {
			return fmt.Errorf("removing the local notes ref: %w", err)
		}
		return nil
	case errors.Is(err, git.NoErrAlreadyUpToDate):
		// The local ref already is the remote's.
		return nil
	default:
		return fmt.Errorf("fetching notes: %w", err)
	}
}

// openOrCloneRepoForNotes opens an existing repository or clones it for notes operations
func (c *Collector) openOrCloneRepoForNotes(ctx context.Context, components *vcslocator.Components) (*git.Repository, error) {
	if components.Transport == vcslocator.TransportFile {
		// Open existing local repository
		localPath, err := vcslocator.Locator(c.Options.Locator).LocalPath()
		if err != nil {
			return nil, fmt.Errorf("resolving local path: %w", err)
		}
		repo, err := git.PlainOpen(localPath)
		if err != nil {
			return nil, fmt.Errorf("opening local repository: %w", err)
		}

		return repo, nil
	}

	// Get authentication method for remote repos. Pass the configured HTTP
	// credentials so cloning works for private repositories, matching pushNotes.
	auth, err := vcslocator.GetAuthMethod(
		c.Options.Locator, vcslocator.WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
	)
	if err != nil {
		return nil, fmt.Errorf("getting auth method: %w", err)
	}

	// For remote repos, clone to memory
	repo, err := git.CloneContext(ctx, memory.NewStorage(), nil, &git.CloneOptions{
		URL:  components.RepoURL(),
		Auth: auth,
		// Clone without checking out a worktree (bare-like clone)
	})
	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return nil, fmt.Errorf("cloning repository: %w", err)
	}

	// Fetch notes explicitly
	err = repo.FetchContext(ctx, &git.FetchOptions{
		Auth: auth,
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("+%s:%s", notesRef, notesRef)),
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		// Notes ref may not exist yet, which is fine
		if !errors.Is(err, git.NoMatchingRefSpecError{}) {
			return nil, fmt.Errorf("fetching notes: %w", err)
		}
	}

	return repo, nil
}

// readExistingBundle reads the existing JSONL bundle from the notes ref
func (c *Collector) readExistingBundle(repo *git.Repository, commitSHA string) (
	existingData []byte, notePath string, isSharded bool, err error,
) {
	// Try to get the notes reference
	notesRefObj, err := repo.Reference(plumbing.ReferenceName(notesRef), true)
	if err != nil {
		if errors.Is(err, plumbing.ErrReferenceNotFound) {
			// Notes ref doesn't exist, will be created
			return nil, commitSHA, false, nil
		}
		return nil, "", false, fmt.Errorf("getting notes reference: %w", err)
	}

	commit, err := repo.CommitObject(notesRefObj.Hash())
	if err != nil {
		return nil, "", false, fmt.Errorf("getting notes commit: %w", err)
	}

	tree, err := commit.Tree()
	if err != nil {
		return nil, "", false, fmt.Errorf("getting notes tree: %w", err)
	}

	// Try sharded path first
	shardedPath := commitSHA[0:2] + "/" + commitSHA[2:]
	file, err := tree.File(shardedPath)
	if err == nil {
		data, err := file.Contents()
		if err != nil {
			return nil, "", false, fmt.Errorf("reading sharded note: %w", err)
		}
		return []byte(data), shardedPath, true, nil
	}

	// Try non-sharded path
	file, err = tree.File(commitSHA)
	if err == nil {
		data, err := file.Contents()
		if err != nil {
			return nil, "", false, fmt.Errorf("reading note: %w", err)
		}
		return []byte(data), commitSHA, false, nil
	}

	// No existing bundle found
	return nil, commitSHA, false, nil
}

// validateJSONL checks if the data is valid JSONL format (one JSON object per line)
func (c *Collector) validateJSONL(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		// Skip empty lines (including trailing newline)
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		// Try to parse as JSON
		var js json.RawMessage
		if err := json.Unmarshal(line, &js); err != nil {
			return fmt.Errorf("line %d is not valid JSON: %w", i+1, err)
		}
	}

	return nil
}

// serializeToJSONL serializes envelopes to JSONL format
func (c *Collector) serializeToJSONL(envelopes []attestation.Envelope) ([]byte, *repository.StoreError) {
	var buf bytes.Buffer
	serr := repository.NewStoreError()

	for i, env := range envelopes {
		data, err := json.Marshal(env)
		if err != nil {
			serr.Failed[i] = fmt.Errorf("marshaling envelope: %w", err)
			continue
		}

		// Writes to a bytes.Buffer never fail
		buf.Write(data)
		buf.WriteByte('\n')
		serr.Stored++
	}

	return buf.Bytes(), serr
}

// shouldShardNotes determines if the notes should be sharded based on repository state
func (c *Collector) shouldShardNotes(repo *git.Repository) bool {
	// Get the notes reference
	notesRefObj, err := repo.Reference(plumbing.ReferenceName(notesRef), true)
	if err != nil {
		// If notes ref doesn't exist, don't shard initially
		return false
	}

	commit, err := repo.CommitObject(notesRefObj.Hash())
	if err != nil {
		return false
	}

	tree, err := commit.Tree()
	if err != nil {
		return false
	}

	// Check if there are any sharded notes (directories with 2-char names)
	hasShardedNotes := false
	tree.Files().ForEach(func(f *object.File) error { //nolint:errcheck,gosec
		if strings.Contains(f.Name, "/") {
			parts := strings.SplitN(f.Name, "/", 2)
			if len(parts[0]) == 2 {
				hasShardedNotes = true
				return fmt.Errorf("found sharded note") // Stop iteration
			}
		}
		return nil
	})

	return hasShardedNotes
}

// updateNotesRef updates the notes ref with new content
func (c *Collector) updateNotesRef(repo *git.Repository, notePath string, data []byte, commitSHA string) error {
	// Get the current notes ref tree (if it exists)
	var baseTree *object.Tree
	notesRefObj, err := repo.Reference(plumbing.ReferenceName(notesRef), true)
	if err == nil {
		// Notes ref exists, get the tree from the last commit
		commit, err := repo.CommitObject(notesRefObj.Hash())
		if err != nil {
			return fmt.Errorf("getting notes commit: %w", err)
		}
		baseTree, err = commit.Tree()
		if err != nil {
			return fmt.Errorf("getting notes tree: %w", err)
		}
	}

	// Create a new tree with the updated note
	newTree, err := c.createUpdatedTree(repo, baseTree, notePath, data)
	if err != nil {
		return fmt.Errorf("creating updated tree: %w", err)
	}

	// Create a commit for the new tree
	var parents []plumbing.Hash
	if notesRefObj != nil {
		parents = []plumbing.Hash{notesRefObj.Hash()}
	}

	now := time.Now()
	commit := &object.Commit{
		Author: object.Signature{
			Name:  "Carabiner Collector",
			Email: "noreply@carabiner.dev",
			When:  now,
		},
		Committer: object.Signature{
			Name:  "Carabiner Collector",
			Email: "noreply@carabiner.dev",
			When:  now,
		},
		Message:      fmt.Sprintf("Add attestations for commit %s", commitSHA),
		TreeHash:     newTree,
		ParentHashes: parents,
	}

	// Encode and store the commit
	obj := repo.Storer.NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		return fmt.Errorf("encoding commit: %w", err)
	}
	commitHash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		return fmt.Errorf("storing commit: %w", err)
	}

	// Update the notes ref
	ref := plumbing.NewHashReference(plumbing.ReferenceName(notesRef), commitHash)
	if err := repo.Storer.SetReference(ref); err != nil {
		return fmt.Errorf("updating notes ref: %w", err)
	}

	return nil
}

// createUpdatedTree creates a new tree with the updated note file
func (c *Collector) createUpdatedTree(repo *git.Repository, baseTree *object.Tree, notePath string, data []byte) (plumbing.Hash, error) {
	// Create a blob for the note data
	blob := &object.Blob{}
	blob.Size = int64(len(data))

	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	writer, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("getting blob writer: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("writing blob data: %w", err)
	}
	writer.Close() //nolint:errcheck,gosec

	blobHash, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("storing blob: %w", err)
	}

	// Build the tree entries
	entries := []object.TreeEntry{}

	// If we have a base tree, copy existing entries (excluding the one we're updating)
	if baseTree != nil {
		for _, entry := range baseTree.Entries {
			if entry.Name != notePath && !strings.HasPrefix(entry.Name+"/", notePath+"/") {
				entries = append(entries, entry)
			}
		}
	}

	// Handle sharded paths (e.g., "ab/cdef...")
	if strings.Contains(notePath, "/") {
		// Create subtree for sharded notes
		parts := strings.SplitN(notePath, "/", 2)
		dirName := parts[0]
		fileName := parts[1]

		// Create subtree with the file
		subTree := &object.Tree{
			Entries: []object.TreeEntry{
				{
					Name: fileName,
					Mode: filemode.Regular,
					Hash: blobHash,
				},
			},
		}

		subTreeObj := repo.Storer.NewEncodedObject()
		if err := subTree.Encode(subTreeObj); err != nil {
			return plumbing.ZeroHash, fmt.Errorf("encoding subtree: %w", err)
		}
		subTreeHash, err := repo.Storer.SetEncodedObject(subTreeObj)
		if err != nil {
			return plumbing.ZeroHash, fmt.Errorf("storing subtree: %w", err)
		}

		// Add directory entry
		entries = append(entries, object.TreeEntry{
			Name: dirName,
			Mode: filemode.Dir,
			Hash: subTreeHash,
		})
	} else {
		// Add file entry at root
		entries = append(entries, object.TreeEntry{
			Name: notePath,
			Mode: filemode.Regular,
			Hash: blobHash,
		})
	}

	// Sort entries by name (required by git)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	// Create the root tree
	tree := &object.Tree{
		Entries: entries,
	}

	treeObj := repo.Storer.NewEncodedObject()
	if err := tree.Encode(treeObj); err != nil {
		return plumbing.ZeroHash, fmt.Errorf("encoding tree: %w", err)
	}
	treeHash, err := repo.Storer.SetEncodedObject(treeObj)
	if err != nil {
		return plumbing.ZeroHash, fmt.Errorf("storing tree: %w", err)
	}

	return treeHash, nil
}

// pushNotes pushes the notes ref to the remote
func (c *Collector) pushNotes(ctx context.Context, repo *git.Repository) error {
	// Get authentication method
	auth, err := vcslocator.GetAuthMethod(
		c.Options.Locator, vcslocator.WithHttpAuth(c.Options.HttpUsername, c.Options.HttpPassword),
	)
	if err != nil {
		return fmt.Errorf("getting auth method: %w", err)
	}

	// Get remote
	remote, err := repo.Remote("origin")
	if err != nil {
		return fmt.Errorf("getting remote: %w", err)
	}

	// Push the notes ref
	err = remote.PushContext(ctx, &git.PushOptions{
		Auth: auth,
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("%s:%s", notesRef, notesRef)),
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("pushing notes: %w", err)
	}

	return nil
}
