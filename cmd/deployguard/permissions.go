package main

import (
	"context"
	"log/slog"
	"sort"
)

// permissionSource reports the permissions the GitHub App is configured with.
type permissionSource interface {
	Permissions(ctx context.Context) (map[string]string, error)
}

// neededPermissions lists what the enabled features require. Values are the minimum access level.
func neededPermissions(config serverConfig) map[string]string {
	needs := map[string]string{"metadata": "read", "checks": "write", "actions": "read", "pull_requests": "read"}
	if config.prComments {
		needs["pull_requests"] = "write"
	}
	if config.provenanceRoot != "" {
		needs["attestations"] = "read"
	}
	return needs
}

// satisfies reports whether a granted level covers the needed one ("write" covers "read").
func satisfies(have, need string) bool {
	return have == need || (need == "read" && have == "write")
}

// checkPermissions logs, at startup, any permission an enabled feature needs that the App does not
// have. It never stops the server: a failed lookup or a missing permission only produces a warning
// that says exactly what to change, instead of a generic 403 on every later request.
func checkPermissions(ctx context.Context, source permissionSource, config serverConfig, logger *slog.Logger) {
	have, err := source.Permissions(ctx)
	if err != nil {
		logger.Warn("could not check the GitHub App's permissions", "error", err.Error())
		return
	}
	needs := neededPermissions(config)
	names := make([]string, 0, len(needs))
	for name := range needs {
		names = append(names, name)
	}
	sort.Strings(names)
	missing := 0
	for _, name := range names {
		if !satisfies(have[name], needs[name]) {
			missing++
			logger.Warn("the GitHub App is missing a permission an enabled feature needs",
				"permission", name, "needed", needs[name], "configured", have[name],
				"fix", "change it in the App's settings, then have the installation owner accept the change")
		}
	}
	if missing == 0 {
		logger.Info("GitHub App permissions cover the enabled features")
	}
}
