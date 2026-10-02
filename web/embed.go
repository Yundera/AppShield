// Package web holds the gate's own pages, compiled into the binary.
//
// 2.x shipped login.html to /usr/share/nginx/html but the auth service looked
// for it at /app/login.html — a path the Dockerfile never created — so the
// polished page was dead code and users always saw an inline fallback. Embedding
// removes the possibility of that class of mismatch.
package web

import _ "embed"

//go:embed login.html
var LoginHTML []byte

//go:embed 403.html
var ForbiddenHTML []byte

// UnavailableHTML is an html/template, not static bytes: it carries the
// optional setup link and the URL its refresh goes back to. See oidcrp.
//
//go:embed unavailable.html
var UnavailableHTML string
