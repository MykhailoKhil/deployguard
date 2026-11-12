// Package assets embeds the project's static brand files into the binary, so the server needs
// nothing on disk at run time and a release binary or Docker image carries them automatically.
package assets

import "embed"

// Brand holds the SVG logos in brand/: the mark, the light and dark wordmarks, and the social banner.
//
//go:embed brand/*.svg
var Brand embed.FS
