// Package web embeds the console front end (plain Vue 3 global build, no bundler needed).
package web

import "embed"

//go:embed index.html app.js style.css vendor
var FS embed.FS
