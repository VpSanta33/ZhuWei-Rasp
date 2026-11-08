// Package web embeds the compiled Vue console. Run npm ci && npm run build here before go build.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// FS serves only compiled public assets, never frontend source or dependencies.
var FS = publicFS()

func publicFS() fs.FS {
	public, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	return public
}
