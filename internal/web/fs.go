// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"io/fs"
	"os"
)

// stderr is indirected so tests can capture it.
var stderr = os.Stderr

func fsSub(f fs.FS, dir string) (fs.FS, error) { return fs.Sub(f, dir) }
