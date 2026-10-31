package permissions

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/go-github/v62/github"
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
		t.Fatalf("failed to parse server url: %v", err)
	}
	client.BaseURL = u
	return client
}

func TestLookupCuratedAction(t *testing.T) {
	tests := []struct {
		action string
		with   map[string]string
		want   PermissionSet
	}{
		{
			action: "actions/checkout",
			want:   PermissionSet{"contents": AccessRead},
		},
		{
			action: "github/codeql-action/upload-sarif",
			want: PermissionSet{
				"security-events": AccessWrite,
				"actions":         AccessRead,
				"contents":        AccessRead,
			},
		},
		{
			action: "actions/cache",
			want:   PermissionSet{"contents": AccessRead},
		},
		{
			action: "softprops/action-gh-release",
			want:   PermissionSet{"contents": AccessWrite},
		},
		{
			action: "peter-evans/create-pull-request",
			want: PermissionSet{
				"contents":      AccessWrite,
				"pull-requests": AccessWrite,
			},
		},
		{
			action: "docker/login-action",
			with:   map[string]string{"registry": "ghcr.io"},
			want: PermissionSet{
				"packages": AccessWrite,
				"contents": AccessRead,
			},
		},
		{
			action: "docker/build-push-action",
			want: PermissionSet{
				"packages": AccessWrite,
				"contents": AccessRead,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got, ok := LookupCuratedAction(tc.action, tc.with)
			if !ok {
				t.Fatalf("LookupCuratedAction(%q) returned false, want true", tc.action)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("LookupCuratedAction(%q) = %v, want %v", tc.action, got, tc.want)
			}
		})
	}
}

func TestAnalyzeRunScript(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   PermissionSet
	}{
		{
			name:   "git push requires contents write",
			script: "git commit -am 'bump'\ngit push origin main",
			want:   PermissionSet{"contents": AccessWrite},
		},
		{
			name:   "gh release create requires contents write",
			script: "gh release create v1.0.0 ./dist/*.tar.gz",
			want:   PermissionSet{"contents": AccessWrite},
		},
		{
			name:   "gh pr create and comment require pull-requests write",
			script: "gh pr create --fill\ngh pr comment 42 --body 'LGTM'",
			want:   PermissionSet{"pull-requests": AccessWrite},
		},
		{
			name:   "gh issue requires issues write",
			script: "gh issue create --title 'Bug report' --body 'Details'",
			want:   PermissionSet{"issues": AccessWrite},
		},
		{
			name:   "benign build script requires no elevated permissions",
			script: "go build ./...\ngo test -v ./...",
			want:   PermissionSet{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeRunScript(tc.script)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AnalyzeRunScript() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInferJobPermissionsLatticeAndUpstreamFetch(t *testing.T) {
	upstreamActionYAML := `name: Custom Security Scanner
description: "Uploads reports. Requires checks: write and statuses: read"
permissions:
  checks: write
  statuses: read
inputs:
  token:
    description: "GitHub token with id-token: write for OIDC"
`
	encodedYAML := base64.StdEncoding.EncodeToString([]byte(upstreamActionYAML))

	client := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/custom-scanner/contents/action.yml" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"type":"file","encoding":"base64","content":%q}`, encodedYAML)
			return
		}
		http.NotFound(w, r)
	})

	ext := NewExtractor(client)
	steps := []StepInput{
		{
			Uses: "actions/checkout@v4",
		},
		{
			Uses:        "acme/custom-scanner@v1",
			ResolvedSHA: "1234567890abcdef1234567890abcdef12345678",
		},
		{
			Run: "git push origin HEAD\ngh pr comment 10 --body 'Updated'",
		},
	}

	got := ext.InferJobPermissions(context.Background(), steps)
	want := PermissionSet{
		"contents":      AccessWrite, // lattice upgrade: checkout (read) + git push (write) => write
		"checks":        AccessWrite, // from upstream action.yml
		"statuses":      AccessRead,  // from upstream action.yml
		"id-token":      AccessWrite, // from upstream input description
		"pull-requests": AccessWrite, // from run script (gh pr comment)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("InferJobPermissions() = %v, want %v", got, want)
	}
}

func TestInferJobPermissionsDefaultFallback(t *testing.T) {
	ext := NewExtractor(nil)
	steps := []StepInput{
		{
			Run: "echo 'Hello world'\ngo test ./...",
		},
	}

	got := ext.InferJobPermissions(context.Background(), steps)
	want := PermissionSet{
		"contents": AccessRead,
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("InferJobPermissions fallback = %v, want %v", got, want)
	}
}
