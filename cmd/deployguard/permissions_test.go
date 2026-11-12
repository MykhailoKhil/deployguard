package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

type fakePermissions struct {
	have map[string]string
	err  error
}

func (f fakePermissions) Permissions(context.Context) (map[string]string, error) {
	return f.have, f.err
}

func capture(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, nil)), &buf
}

func TestNeededPermissionsFollowTheEnabledFeatures(t *testing.T) {
	base := neededPermissions(serverConfig{})
	if base["checks"] != "write" || base["actions"] != "read" || base["pull_requests"] != "read" || base["metadata"] != "read" || len(base) != 4 {
		t.Errorf("base permissions %v", base)
	}
	if got := neededPermissions(serverConfig{prComments: true})["pull_requests"]; got != "write" {
		t.Errorf("comments need Pull requests: write, got %q", got)
	}
	if got := neededPermissions(serverConfig{provenanceRoot: "/x"})["attestations"]; got != "read" {
		t.Errorf("provenance needs Attestations: read, got %q", got)
	}
	if _, ok := base["attestations"]; ok {
		t.Error("attestations must not be required by default")
	}
}

func TestSatisfiesTreatsWriteAsCoveringRead(t *testing.T) {
	for _, tc := range []struct {
		have, need string
		want       bool
	}{{"read", "read", true}, {"write", "read", true}, {"write", "write", true}, {"read", "write", false}, {"", "read", false}, {"", "write", false}} {
		if got := satisfies(tc.have, tc.need); got != tc.want {
			t.Errorf("satisfies(%q,%q) = %v", tc.have, tc.need, got)
		}
	}
}

func TestStartupCheckWarnsPerMissingPermissionAndNamesTheFix(t *testing.T) {
	logger, buf := capture(t)
	checkPermissions(context.Background(), fakePermissions{have: map[string]string{
		"metadata": "read", "checks": "write", "actions": "read", "pull_requests": "read",
	}}, serverConfig{prComments: true, provenanceRoot: "/x"}, logger)
	out := buf.String()
	for _, want := range []string{"pull_requests", "needed=write", "configured=read", "attestations", "needed=read", "accept the change"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "missing a permission") != 2 || strings.Contains(out, "cover the enabled features") {
		t.Errorf("expected exactly two warnings and no all-clear:\n%s", out)
	}
}

func TestStartupCheckIsQuietWhenPermissionsAreEnough(t *testing.T) {
	logger, buf := capture(t)
	checkPermissions(context.Background(), fakePermissions{have: map[string]string{
		"metadata": "read", "checks": "write", "actions": "read", "pull_requests": "write", "attestations": "read",
	}}, serverConfig{prComments: true, provenanceRoot: "/x"}, logger)
	if strings.Contains(buf.String(), "WARN") || !strings.Contains(buf.String(), "cover the enabled features") {
		t.Errorf("unexpected output:\n%s", buf.String())
	}
}

func TestStartupCheckNeverFailsWhenGitHubIsUnreachable(t *testing.T) {
	logger, buf := capture(t)
	checkPermissions(context.Background(), fakePermissions{err: errors.New("look up the GitHub App")}, serverConfig{}, logger)
	if !strings.Contains(buf.String(), "could not check") {
		t.Errorf("a failed lookup is a warning, got:\n%s", buf.String())
	}
}
