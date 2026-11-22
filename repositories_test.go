// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package collector

import (
	"fmt"
	"sync"
	"testing"

	"github.com/policylabs/attestation"
	"github.com/stretchr/testify/require"

	"github.com/policylabs/collector/repository/filesystem"
)

// The registry is read while it is written: a program loads the default
// types on first use, and builds repositories from init strings on other
// goroutines meanwhile. Run with -race, this is where a registry that reads
// without its lock shows.
func TestRegistryIsSafeForConcurrentUse(t *testing.T) {
	const workers, rounds = 8, 200

	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := range workers {
		wg.Add(4)
		// Loads of the default types, the first of which writes them all.
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				if err := LoadDefaultRepositoryTypes(); err != nil {
					t.Errorf("loading default types: %v", err)
					return
				}
			}
		}()
		// Lookups, of a type that is there sooner or later and of one that
		// never is.
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				_, _ = RepositoryFromString(filesystem.TypeMoniker + ":testdata") //nolint:errcheck // the type may not be loaded yet
				if _, err := RepositoryFromString("nonesuch:x"); err == nil {
					t.Error("an unregistered type built a repository")
					return
				}
			}
		}()
		// Types of the worker's own, registered and removed.
		moniker := fmt.Sprintf("racetest%d", w)
		factory := func(string) (attestation.Repository, error) { return nil, nil } //nolint:nilnil // a factory that builds nothing is enough here
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				_ = RegisterCollectorType(moniker, factory) //nolint:errcheck // it may still be registered from the last round
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				UnregisterCollectorType(moniker)
			}
		}()
	}
	close(start)
	wg.Wait()

	for w := range workers {
		UnregisterCollectorType(fmt.Sprintf("racetest%d", w))
	}
}

// Registering a moniker twice keeps the first factory and says so.
func TestRegisterCollectorType(t *testing.T) {
	const moniker = "registertest"
	t.Cleanup(func() { UnregisterCollectorType(moniker) })

	built := ""
	first := func(string) (attestation.Repository, error) { built = "first"; return nil, nil }   //nolint:nilnil // builds nothing
	second := func(string) (attestation.Repository, error) { built = "second"; return nil, nil } //nolint:nilnil // builds nothing

	require.NoError(t, RegisterCollectorType(moniker, first))
	require.ErrorIs(t, RegisterCollectorType(moniker, second), ErrTypeAlreadyRegistered)

	_, err := RepositoryFromString(moniker + ":anything")
	require.NoError(t, err)
	require.Equal(t, "first", built)

	UnregisterCollectorType(moniker)
	_, err = RepositoryFromString(moniker + ":anything")
	require.ErrorContains(t, err, "repository type unknown")
}
