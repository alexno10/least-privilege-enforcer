package gitpr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-github/v62/github"

	"github.com/alexno10/least-privilege-enforcer/internal/ast"
	"github.com/alexno10/least-privilege-enforcer/internal/permissions"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newMockGitHubClient(t *testing.T, handler http.HandlerFunc) *github.Client {
	t.Helper()
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			return rec.Result(), nil
		}),
	}
	client := github.NewClient(httpClient)
	u, err := url.Parse("http://api.github.local/")
	if err != nil {
		t.Fatalf("failed to parse url: %v", err)
	}
	client.BaseURL = u
	return client
}

func TestBuildPRBodyAndUnifiedDiff(t *testing.T) {
	changes := []WorkflowChange{
		{
			RepoRelativePath: ".github/workflows/vulnerable.yml",
			OriginalBytes:    []byte("uses: actions/checkout@v4\n"),
			UpdatedBytes:     []byte("uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4\n"),
			PinnedActions: []ast.PinnedAction{
				{
					Workflow:  "vulnerable.yml",
					JobID:     "build",
					Action:    "actions/checkout",
					OldRef:    "v4",
					PinnedSHA: "b4ffde65f46336ab88eb53be808477a3936bae11",
				},
			},
			JobPermissions: []ast.JobPermissionsRecord{
				{
					Workflow: "vulnerable.yml",
					JobID:    "build",
					Permissions: permissions.PermissionSet{
						"contents":      permissions.AccessRead,
						"pull-requests": permissions.AccessWrite,
					},
				},
			},
		},
	}

	body := BuildPRBody(changes)
	if !strings.Contains(body, "| `actions/checkout` | `v4` | `b4ffde65f46336ab88eb53be808477a3936bae11` |") {
		t.Errorf("PR body missing pinned actions row:\n%s", body)
	}
	if !strings.Contains(body, "| `vulnerable.yml` | `build` | `contents: read`, `pull-requests: write` |") {
		t.Errorf("PR body missing job permissions row:\n%s", body)
	}

	diff := GenerateUnifiedDiff(changes[0].RepoRelativePath, changes[0].OriginalBytes, changes[0].UpdatedBytes)
	if !strings.Contains(diff, "-uses: actions/checkout@v4") || !strings.Contains(diff, "+uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4") {
		t.Errorf("unexpected unified diff output:\n%s", diff)
	}
}

func TestCreateOrUpdatePRIdempotency(t *testing.T) {
	existingPRMode := false

	client := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/demo":
			fmt.Fprint(w, `{"default_branch":"main"}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/demo/git/ref/heads/main":
			fmt.Fprint(w, `{"ref":"refs/heads/main","object":{"sha":"aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/demo/pulls":
			if existingPRMode {
				fmt.Fprint(w, `[{"number":77,"html_url":"https://github.com/acme/demo/pull/77","head":{"ref":"security/least-privilege-enforcer-1000"}}]`)
			} else {
				fmt.Fprint(w, `[]`)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/demo/git/trees":
			fmt.Fprint(w, `{"sha":"bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/demo/git/commits":
			fmt.Fprint(w, `{"sha":"cccc3333cccc3333cccc3333cccc3333cccc3333"}`)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/repos/acme/demo/git/ref/heads/security/least-privilege-enforcer"):
			if existingPRMode {
				fmt.Fprint(w, `{"ref":"refs/heads/security/least-privilege-enforcer-1000","object":{"sha":"dddd4444dddd4444dddd4444dddd4444dddd4444"}}`)
			} else {
				http.NotFound(w, r)
			}
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/demo/git/refs":
			fmt.Fprint(w, `{"ref":"refs/heads/security/least-privilege-enforcer-1700000000"}`)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/repos/acme/demo/git/refs/heads/security/least-privilege-enforcer"):
			fmt.Fprint(w, `{"ref":"refs/heads/security/least-privilege-enforcer-1000"}`)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/demo/pulls":
			fmt.Fprint(w, `{"number":42,"html_url":"https://github.com/acme/demo/pull/42"}`)
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/demo/pulls/77":
			fmt.Fprint(w, `{"number":77,"html_url":"https://github.com/acme/demo/pull/77"}`)
		default:
			http.NotFound(w, r)
		}
	})

	creator := NewPRCreator(client)
	creator.nowFn = func() time.Time { return time.Unix(1700000000, 0) }

	changes := []WorkflowChange{
		{
			RepoRelativePath: ".github/workflows/ci.yml",
			OriginalBytes:    []byte("on: push\n"),
			UpdatedBytes:     []byte("on: push\npermissions: {}\n"),
		},
	}

	// 1. Fresh PR creation
	res1, err := creator.CreateOrUpdatePR(context.Background(), "acme", "demo", changes)
	if err != nil {
		t.Fatalf("CreateOrUpdatePR (new) failed: %v", err)
	}
	if res1.UpdatedExisting || res1.PRNumber != 42 || res1.BranchName != "security/least-privilege-enforcer-1700000000" {
		t.Errorf("unexpected new PR result: %+v", res1)
	}

	// 2. Idempotent update when an open PR already exists
	existingPRMode = true
	res2, err := creator.CreateOrUpdatePR(context.Background(), "acme", "demo", changes)
	if err != nil {
		t.Fatalf("CreateOrUpdatePR (existing) failed: %v", err)
	}
	if !res2.UpdatedExisting || res2.PRNumber != 77 || res2.BranchName != "security/least-privilege-enforcer-1000" {
		t.Errorf("unexpected existing PR update result: %+v", res2)
	}
}
