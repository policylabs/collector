// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/policylabs/attestation"

	"github.com/policylabs/collector/repository"
	"github.com/policylabs/collector/repository/actions"
	"github.com/policylabs/collector/repository/coci"
	"github.com/policylabs/collector/repository/filesystem"
	"github.com/policylabs/collector/repository/git"
	"github.com/policylabs/collector/repository/github"
	"github.com/policylabs/collector/repository/gitsign"
	"github.com/policylabs/collector/repository/http"
	"github.com/policylabs/collector/repository/jsonl"
	"github.com/policylabs/collector/repository/maven"
	"github.com/policylabs/collector/repository/note"
	"github.com/policylabs/collector/repository/oci"
	"github.com/policylabs/collector/repository/ossrebuild"
	"github.com/policylabs/collector/repository/pypi"
	"github.com/policylabs/collector/repository/release"
	"github.com/policylabs/collector/repository/sbomfs"
	"github.com/policylabs/collector/repository/stash"
)

var (
	repositoryTypes          = map[string]RepositoryFactory{}
	ErrTypeAlreadyRegistered = errors.New("collector type already registered")
)

type RepositoryFactory func(string) (attestation.Repository, error)

// mtx guards repositoryTypes. The registry is read on every repository built
// from an init string and written when types are registered, which a
// program may do while it is already serving: both take the lock.
var mtx sync.RWMutex

// RepositoryFromString builds the repository an init string names: the type
// before the first colon, handed what follows it.
func RepositoryFromString(init string) (attestation.Repository, error) {
	t, init, _ := strings.Cut(init, ":")
	mtx.RLock()
	build, ok := repositoryTypes[t]
	mtx.RUnlock()
	if !ok {
		return nil, fmt.Errorf("repository type unknown: %q", t)
	}
	// The factory runs outside the lock: it may be slow, and it may build
	// repositories of other types itself.
	return build(init)
}

// RegisterCollectorType registers a new type of collector. A moniker that
// is already registered keeps its factory, and the call answers
// ErrTypeAlreadyRegistered.
func RegisterCollectorType(moniker string, factory RepositoryFactory) error {
	mtx.Lock()
	defer mtx.Unlock()
	if _, ok := repositoryTypes[moniker]; ok {
		return ErrTypeAlreadyRegistered
	}
	repositoryTypes[moniker] = factory
	return nil
}

// UnregisterCollectorType removes a type of collector from the registry.
func UnregisterCollectorType(moniker string) {
	mtx.Lock()
	delete(repositoryTypes, moniker)
	mtx.Unlock()
}

// LoadDefaultRepositoryTypes loads the default repository types into the
// in-memory list to get them ready for instantiation.
func LoadDefaultRepositoryTypes() error {
	errs := []error{}
	for t, factory := range map[string]RepositoryFactory{
		actions.TypeMoniker:     actions.Build,
		coci.TypeMoniker:        coci.Build,
		filesystem.TypeMoniker:  filesystem.Build,
		git.TypeMoniker:         git.Build,
		oci.TypeMoniker:         oci.Build,
		gitsign.TypeMoniker:     gitsign.Build,
		github.TypeMoniker:      github.Build,
		http.TypeMoniker:        http.BuildHTTP,
		http.TypeMonikerHTTPS:   http.BuildHTTPs,
		jsonl.TypeMoniker:       jsonl.Build,
		maven.TypeMoniker:       maven.Build,
		note.TypeMoniker:        note.Build,
		note.TypeMonikerDynamic: note.BuildDynamic,
		ossrebuild.TypeMoniker:  ossrebuild.Build,
		pypi.TypeMoniker:        pypi.Build,
		release.TypeMoniker:     release.Build,
		sbomfs.TypeMoniker:      sbomfs.Build,
		stash.TypeMoniker:       stash.Build,
	} {
		if err := RegisterCollectorType(t, factory); err != nil {
			if !errors.Is(err, ErrTypeAlreadyRegistered) {
				errs = append(errs, err)
			}
		}
	}
	// The repository types that keep content only they can read back
	for t, reassembler := range map[string]repository.Reassembler{
		gitsign.TypeMoniker: gitsign.Reassemble,
		pypi.TypeMoniker:    pypi.Reassemble,
	} {
		if err := RegisterReassembler(t, reassembler); err != nil {
			if !errors.Is(err, ErrTypeAlreadyRegistered) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
