// Copyright 2026 Canonical.

// Command legacywire writes the golden snapshot of the Juju 3.6 wire-struct
// signatures JIMM serves (see internal/jujuapi/legacywire). It is run
// via go:generate and `make update-golden`, and its output is guarded in CI
// by the verify_generated job.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/canonical/jimm/v3/internal/jujuapi/legacywire"
)

func main() {
	outPath := flag.String("o", "", "output golden file path")
	flag.Parse()

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "missing required -o output path")
		os.Exit(2)
	}

	if err := write(*outPath, legacywire.Golden()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// write atomically writes data to path, creating parent directories as needed.
func write(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	//nolint:gosec // Don't enforce 0o600 or less permission.
	if err := os.WriteFile(tmp, data, 0o664); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
