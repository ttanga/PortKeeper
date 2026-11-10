package admin

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

func SubFS() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
