package util

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ResolveWithin joins rel onto dir and returns the real path of the result,
// refusing anything that lands outside dir.
//
// A run directory is a portable bundle: reports are meant to be handed to someone
// else, and `assets import --from` and `report --run` accept a directory from
// anywhere. Archive extraction preserves symlinks, so a crafted bundle can place a
// symlink where an artifact belongs and make the tool read any file the operator
// can read, then put its contents into a report or the database. rel is always a
// fixed name, so path traversal with ".." is not the risk; a link standing at that
// name is.
//
// Every link along the way is resolved, not just the last component, so a symlink
// standing in for a whole stage folder is caught too. The root is resolved as well,
// because the directory itself may be reached through a link (a temporary directory
// under /var on macOS). The returned path is the resolved one: open that, not the
// joined path, so the check and the read agree on which file is meant.
//
// A path that does not exist is not an error here. It comes back unresolved, so
// the caller's open reports "absent", which the project distinguishes from "broken".
func ResolveWithin(dir, rel string) (string, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A directory that is not there is "absent": the caller's open will
			// say so, which is a different answer from "broken".
			return filepath.Join(dir, rel), nil
		}
		// Anything else (permission denied, a loop) is a real problem with the
		// directory and must not be mistaken for a missing one.
		return "", fmt.Errorf("could not resolve the run directory: %w", err)
	}
	full := filepath.Join(root, rel)
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return full, nil
		}
		return "", fmt.Errorf("could not resolve %s: %w", rel, err)
	}
	if resolved != root && !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("%s resolves outside the run directory to %s", rel, resolved)
	}
	return resolved, nil
}
