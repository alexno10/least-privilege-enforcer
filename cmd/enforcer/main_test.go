package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigFlagsAndEnv(t *testing.T) {
	env := map[string]string{
		"INPUT_WORKFLOWS_DIR": "custom/workflows",
		"INPUT_DRY_RUN":       "true",
		"INPUT_FORCE":         "true",
		"INPUT_GITHUB_TOKEN":  "ghs_env_token",
		"GITHUB_REPOSITORY":   "octocat/enforcer-demo",
	}
	getenv := func(k string) string { return env[k] }

	// 1. From INPUT_* and GITHUB_* environment variables
	cfgEnv, err := parseConfig(nil, getenv)
	if err != nil {
		t.Fatalf("parseConfig from env failed: %v", err)
	}
	if cfgEnv.WorkflowsDir != "custom/workflows" || !cfgEnv.DryRun || !cfgEnv.Force || cfgEnv.GitHubToken != "ghs_env_token" || cfgEnv.Repo != "octocat/enforcer-demo" {
		t.Errorf("unexpected env config: %+v", cfgEnv)
	}

	// 2. CLI flags override environment variables
	args := []string{
		"--workflows-dir", ".github/workflows",
		"--dry-run=false",
		"--github-token", "ghp_cli_token",
		"--repo", "acme/secops",
	}
	cfgCLI, err := parseConfig(args, getenv)
	if err != nil {
		t.Fatalf("parseConfig from CLI flags failed: %v", err)
	}
	if cfgCLI.WorkflowsDir != ".github/workflows" || cfgCLI.DryRun || cfgCLI.GitHubToken != "ghp_cli_token" || cfgCLI.Repo != "acme/secops" {
		t.Errorf("unexpected CLI config: %+v", cfgCLI)
	}
}

func TestRunDryRunOutputsUnifiedDiff(t *testing.T) {
	tmpDir := t.TempDir()
	wfPath := filepath.Join(tmpDir, "ci.yml")
	content := `name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - run: git push origin main
`
	if err := os.WriteFile(wfPath, []byte(content), 0o644); err != nil {
		t.Fatalf("writing temp workflow failed: %v", err)
	}

	cfg := &Config{
		WorkflowsDir: tmpDir,
		DryRun:       true,
	}

	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), cfg, &stdout, &stderr); err != nil {
		t.Fatalf("run(--dry-run) failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "+permissions: {}") || !strings.Contains(out, "+      contents: write") {
		t.Errorf("expected dry-run diff to contain injected permissions, got:\n%s", out)
	}

	// Ensure original file on disk was NOT modified during --dry-run.
	diskBytes, err := os.ReadFile(wfPath)
	if err != nil {
		t.Fatalf("reading workflow after dry-run: %v", err)
	}
	if string(diskBytes) != content {
		t.Errorf("expected --dry-run not to modify file on disk")
	}
}
