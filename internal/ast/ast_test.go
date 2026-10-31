package ast

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alexno10/least-privilege-enforcer/internal/permissions"
)

type mockSHAResolver struct {
	mapping map[string]string
}

func (m *mockSHAResolver) Resolve(_ context.Context, owner, repo, ref string) (string, error) {
	key := fmt.Sprintf("%s/%s@%s", owner, repo, ref)
	if sha, ok := m.mapping[key]; ok {
		return sha, nil
	}
	return "", fmt.Errorf("unexpected action ref in mock resolver: %s", key)
}

func TestMutateVulnerableWorkflow(t *testing.T) {
	const (
		checkoutV4SHA  = "b4ffde65f46336ab88eb53be808477a3936bae11"
		checkoutMain   = "1111111111111111111111111111111111111111"
		codeqlV3SHA    = "2222222222222222222222222222222222222222"
		ghReleaseV2SHA = "3333333333333333333333333333333333333333"
	)

	mockRes := &mockSHAResolver{
		mapping: map[string]string{
			"actions/checkout@v4.1.1":         checkoutV4SHA,
			"actions/checkout@main":           checkoutMain,
			"github/codeql-action@v3":         codeqlV3SHA,
			"softprops/action-gh-release@v2.0.5": ghReleaseV2SHA,
		},
	}

	vulnPath := filepath.Join("..", "..", "testdata", "workflows", "vulnerable.yml")
	doc, err := ParseWorkflowFile(vulnPath)
	if err != nil {
		t.Fatalf("ParseWorkflowFile failed: %v", err)
	}

	mutator := NewMutator(mockRes, permissions.NewExtractor(nil), MutatorOptions{Force: false})
	res, err := mutator.MutateWorkflow(context.Background(), doc)
	if err != nil {
		t.Fatalf("MutateWorkflow failed: %v", err)
	}

	if !res.Modified {
		t.Fatalf("expected workflow to be marked Modified = true")
	}

	out := string(res.UpdatedBytes)

	// 1. Verify comments are preserved.
	expectedComments := []string{
		"# Supply-Chain Vulnerable CI Workflow",
		"# This header comment must be preserved by the YAML AST mutator.",
		"# Over-privileged top-level token permission",
		"# Job 1: Security scanning without explicit job-level permissions",
		"# Step list comment that must remain attached to steps",
		"# Job 2: Release automation with write-all permissions and shell gh CLI usage",
	}
	for _, comment := range expectedComments {
		if !strings.Contains(out, comment) {
			t.Errorf("expected output YAML to preserve comment %q\nOutput:\n%s", comment, out)
		}
	}

	// 2. Verify actions are pinned with inline # <ref> comments.
	expectedPinnedLines := []string{
		"uses: actions/checkout@" + checkoutV4SHA + " # v4.1.1",
		"uses: github/codeql-action/upload-sarif@" + codeqlV3SHA + " # v3",
		"uses: actions/checkout@" + checkoutMain + " # main",
		"uses: softprops/action-gh-release@" + ghReleaseV2SHA + " # v2.0.5",
	}
	for _, line := range expectedPinnedLines {
		if !strings.Contains(out, line) {
			t.Errorf("expected output YAML to contain pinned line %q\nOutput:\n%s", line, out)
		}
	}

	// 3. Verify local and docker actions are left untouched.
	if !strings.Contains(out, "uses: ./.github/actions/local-helper") {
		t.Errorf("expected local action to remain unmodified\nOutput:\n%s", out)
	}
	if !strings.Contains(out, "uses: docker://alpine:3.19") {
		t.Errorf("expected docker action to remain unmodified\nOutput:\n%s", out)
	}

	// 4. Verify top-level permissions was restricted to {}.
	if !strings.Contains(out, "permissions: {}") {
		t.Errorf("expected top-level permissions to be set to `permissions: {}`\nOutput:\n%s", out)
	}

	// 5. Verify job-level permissions telemetry and values.
	if len(res.JobPermissions) != 2 {
		t.Fatalf("expected 2 job permission records, got %d", len(res.JobPermissions))
	}

	wantJob1Perms := permissions.PermissionSet{
		"actions":         permissions.AccessRead,
		"contents":        permissions.AccessRead,
		"security-events": permissions.AccessWrite,
	}
	if !reflect.DeepEqual(res.JobPermissions[0].Permissions, wantJob1Perms) {
		t.Errorf("job %s permissions = %v, want %v", res.JobPermissions[0].JobID, res.JobPermissions[0].Permissions, wantJob1Perms)
	}

	wantJob2Perms := permissions.PermissionSet{
		"contents":      permissions.AccessWrite,
		"pull-requests": permissions.AccessWrite,
	}
	if !reflect.DeepEqual(res.JobPermissions[1].Permissions, wantJob2Perms) {
		t.Errorf("job %s permissions = %v, want %v", res.JobPermissions[1].JobID, res.JobPermissions[1].Permissions, wantJob2Perms)
	}
}

func TestPreserveExplicitLeastPrivilegePermissionsUnlessForced(t *testing.T) {
	rawYAML := `name: Hardened Workflow
on: [push]
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - run: git push origin main
`
	doc, err := ParseWorkflowBytes("hardened.yml", []byte(rawYAML))
	if err != nil {
		t.Fatalf("ParseWorkflowBytes failed: %v", err)
	}

	// Without --force, explicit job-level `permissions: { contents: read }` must NOT be overwritten.
	mutator := NewMutator(&mockSHAResolver{}, permissions.NewExtractor(nil), MutatorOptions{Force: false})
	res, err := mutator.MutateWorkflow(context.Background(), doc)
	if err != nil {
		t.Fatalf("MutateWorkflow failed: %v", err)
	}
	if len(res.JobPermissions) != 0 {
		t.Errorf("expected 0 job permission modifications when explicit permissions exist and Force=false, got %d", len(res.JobPermissions))
	}

	// With --force, explicit job-level permissions are recalculated and updated to `contents: write`.
	docForced, _ := ParseWorkflowBytes("hardened.yml", []byte(rawYAML))
	forcedMutator := NewMutator(&mockSHAResolver{}, permissions.NewExtractor(nil), MutatorOptions{Force: true})
	resForced, err := forcedMutator.MutateWorkflow(context.Background(), docForced)
	if err != nil {
		t.Fatalf("MutateWorkflow with Force=true failed: %v", err)
	}
	if len(resForced.JobPermissions) != 1 || resForced.JobPermissions[0].Permissions["contents"] != permissions.AccessWrite {
		t.Errorf("expected Force=true to recalculate job permissions to contents:write, got %+v", resForced.JobPermissions)
	}
}
