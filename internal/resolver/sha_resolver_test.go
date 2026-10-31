package resolver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/google/go-github/v62/github"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func newMockGitHubClient(t *testing.T, handler http.HandlerFunc) (*github.Client, *httptest.Server) {
	t.Helper()
	httpClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			return rec.Result(), nil
		}),
	}
	client := github.NewClient(httpClient)
	baseURL, err := url.Parse("http://api.github.local/")
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}
	client.BaseURL = baseURL
	return client, nil
}

func TestParseActionUses(t *testing.T) {
	tests := []struct {
		name     string
		uses     string
		wantOk   bool
		wantRef  ActionRef
		wantName string
	}{
		{
			name:   "standard action",
			uses:   "actions/checkout@v4",
			wantOk: true,
			wantRef: ActionRef{
				Owner: "actions",
				Repo:  "checkout",
				Ref:   "v4",
			},
			wantName: "actions/checkout",
		},
		{
			name:   "subpath action",
			uses:   "github/codeql-action/upload-sarif@v3.25.1",
			wantOk: true,
			wantRef: ActionRef{
				Owner:   "github",
				Repo:    "codeql-action",
				Subpath: "upload-sarif",
				Ref:     "v3.25.1",
			},
			wantName: "github/codeql-action/upload-sarif",
		},
		{
			name:   "local action ignored",
			uses:   "./.github/actions/custom-build",
			wantOk: false,
		},
		{
			name:   "docker reference ignored",
			uses:   "docker://alpine:3.19",
			wantOk: false,
		},
		{
			name:   "missing ref ignored",
			uses:   "actions/checkout",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseActionUses(tc.uses)
			if ok != tc.wantOk {
				t.Fatalf("ParseActionUses(%q) ok = %v, want %v", tc.uses, ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if *got != tc.wantRef {
				t.Errorf("ParseActionUses(%q) = %+v, want %+v", tc.uses, *got, tc.wantRef)
			}
			if got.ActionName() != tc.wantName {
				t.Errorf("ActionName() = %q, want %q", got.ActionName(), tc.wantName)
			}
		})
	}
}

func TestResolveLightweightTagAndCache(t *testing.T) {
	const wantSHA = "b4ffde65f46336ab88eb53be808477a3936bae11"
	var apiHits atomic.Int32

	client, _ := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		if r.URL.Path != "/repos/actions/checkout/git/ref/tags/v4" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ref":"refs/tags/v4","object":{"type":"commit","sha":%q}}`, wantSHA)
	})

	res := NewGitHubResolver(client)
	ctx := context.Background()

	// First call hits the API.
	sha1, err := res.Resolve(ctx, "actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}
	if sha1 != wantSHA {
		t.Errorf("got SHA %q, want %q", sha1, wantSHA)
	}

	// Second call must hit the in-memory cache without making another network call.
	sha2, err := res.Resolve(ctx, "actions", "checkout", "v4")
	if err != nil {
		t.Fatalf("cached Resolve failed: %v", err)
	}
	if sha2 != wantSHA {
		t.Errorf("got cached SHA %q, want %q", sha2, wantSHA)
	}
	if hits := apiHits.Load(); hits != 1 {
		t.Errorf("expected 1 API hit due to caching, got %d", hits)
	}
}

func TestResolveAnnotatedTagRecursiveDereference(t *testing.T) {
	const (
		outerTagSHA = "1111111111111111111111111111111111111111"
		innerTagSHA = "2222222222222222222222222222222222222222"
		commitSHA   = "3333333333333333333333333333333333333333"
	)

	client, _ := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/softprops/action-gh-release/git/ref/tags/v2.0.5":
			fmt.Fprintf(w, `{"ref":"refs/tags/v2.0.5","object":{"type":"tag","sha":%q}}`, outerTagSHA)
		case "/repos/softprops/action-gh-release/git/tags/" + outerTagSHA:
			fmt.Fprintf(w, `{"sha":%q,"object":{"type":"tag","sha":%q}}`, outerTagSHA, innerTagSHA)
		case "/repos/softprops/action-gh-release/git/tags/" + innerTagSHA:
			fmt.Fprintf(w, `{"sha":%q,"object":{"type":"commit","sha":%q}}`, innerTagSHA, commitSHA)
		default:
			http.NotFound(w, r)
		}
	})

	res := NewGitHubResolver(client)
	got, err := res.Resolve(context.Background(), "softprops", "action-gh-release", "v2.0.5")
	if err != nil {
		t.Fatalf("Resolve annotated tag failed: %v", err)
	}
	if got != commitSHA {
		t.Errorf("got SHA %q, want underlying commit SHA %q", got, commitSHA)
	}
}

func TestResolveBranchFallback(t *testing.T) {
	const branchCommitSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	client, _ := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/octocat/hello-world/git/ref/tags/main":
			http.NotFound(w, r)
		case "/repos/octocat/hello-world/git/ref/heads/main":
			fmt.Fprintf(w, `{"ref":"refs/heads/main","object":{"type":"commit","sha":%q}}`, branchCommitSHA)
		default:
			http.NotFound(w, r)
		}
	})

	res := NewGitHubResolver(client)
	got, err := res.Resolve(context.Background(), "octocat", "hello-world", "main")
	if err != nil {
		t.Fatalf("Resolve branch failed: %v", err)
	}
	if got != branchCommitSHA {
		t.Errorf("got SHA %q, want %q", got, branchCommitSHA)
	}
}

func TestResolveAlreadyPinnedSHA(t *testing.T) {
	const existingSHA = "B4FFDE65F46336AB88EB53BE808477A3936BAE11"
	var apiHits atomic.Int32

	client, _ := newMockGitHubClient(t, func(w http.ResponseWriter, r *http.Request) {
		apiHits.Add(1)
		http.NotFound(w, r)
	})

	res := NewGitHubResolver(client)
	got, err := res.Resolve(context.Background(), "actions", "checkout", existingSHA)
	if err != nil {
		t.Fatalf("Resolve existing SHA failed: %v", err)
	}
	if got != "b4ffde65f46336ab88eb53be808477a3936bae11" {
		t.Errorf("got %q, want lowercase SHA", got)
	}
	if apiHits.Load() != 0 {
		t.Errorf("expected 0 API calls for already-pinned 40-char SHA, got %d", apiHits.Load())
	}
}
