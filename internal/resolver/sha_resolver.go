package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"
)

const maxTagDereferenceDepth = 10

// SHAResolver resolves a mutable Git reference (tag or branch) to an immutable 40-char commit SHA.
type SHAResolver interface {
	Resolve(ctx context.Context, owner, repo, ref string) (string, error)
}

// ActionRef represents a parsed GitHub Action reference from a workflow step's `uses:` field.
type ActionRef struct {
	Owner   string
	Repo    string
	Subpath string
	Ref     string
}

// ActionName returns the full action path without the @ref suffix (e.g., "actions/checkout" or "github/codeql-action/upload-sarif").
func (a ActionRef) ActionName() string {
	if a.Subpath != "" {
		return fmt.Sprintf("%s/%s/%s", a.Owner, a.Repo, a.Subpath)
	}
	return fmt.Sprintf("%s/%s", a.Owner, a.Repo)
}

// FormatPinned returns the `uses:` value pinned to the given commit SHA.
func (a ActionRef) FormatPinned(sha string) string {
	return fmt.Sprintf("%s@%s", a.ActionName(), sha)
}

// ParseActionUses parses a GitHub Actions `uses:` value.
// It returns (nil, false) for local actions ("./...") and Docker references ("docker://...").
func ParseActionUses(uses string) (*ActionRef, bool) {
	trimmed := strings.TrimSpace(uses)
	if trimmed == "" {
		return nil, false
	}

	// Ignore local actions and Docker container references.
	if strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, ".\\") {
		return nil, false
	}
	if strings.HasPrefix(strings.ToLower(trimmed), "docker://") {
		return nil, false
	}

	atIdx := strings.LastIndex(trimmed, "@")
	if atIdx <= 0 || atIdx == len(trimmed)-1 {
		return nil, false
	}

	target := trimmed[:atIdx]
	ref := trimmed[atIdx+1:]

	parts := strings.Split(target, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, false
	}

	var subpath string
	if len(parts) > 2 {
		subpath = strings.Join(parts[2:], "/")
	}

	return &ActionRef{
		Owner:   parts[0],
		Repo:    parts[1],
		Subpath: subpath,
		Ref:     ref,
	}, true
}

// IsFullCommitSHA returns true if s is a 40-character hexadecimal Git commit SHA.
func IsFullCommitSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// GitHubResolver resolves Git tags and branches to 40-character commit SHAs using the GitHub API,
// with an in-memory cache to avoid redundant requests.
type GitHubResolver struct {
	client *github.Client
	mu     sync.RWMutex
	cache  map[string]string
}

// NewGitHubResolver creates a new GitHubResolver using the provided go-github client.
func NewGitHubResolver(client *github.Client) *GitHubResolver {
	if client == nil {
		client = github.NewClient(nil)
	}
	return &GitHubResolver{
		client: client,
		cache:  make(map[string]string),
	}
}

// NewGitHubResolverWithToken creates a new GitHubResolver authenticated with the given OAuth2/PAT token.
func NewGitHubResolverWithToken(ctx context.Context, token string) *GitHubResolver {
	var httpClient *http.Client
	if strings.TrimSpace(token) != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: strings.TrimSpace(token)})
		httpClient = oauth2.NewClient(ctx, ts)
	}
	return NewGitHubResolver(github.NewClient(httpClient))
}

// Resolve resolves owner/repo@ref to a 40-character commit SHA.
// It handles lightweight tags, annotated tags (recursively dereferencing tag objects), and branches.
func (r *GitHubResolver) Resolve(ctx context.Context, owner, repo, ref string) (string, error) {
	owner = strings.TrimSpace(owner)
	repo = strings.TrimSpace(repo)
	ref = strings.TrimSpace(ref)

	if owner == "" || repo == "" || ref == "" {
		return "", fmt.Errorf("invalid action reference: owner=%q repo=%q ref=%q", owner, repo, ref)
	}

	if IsFullCommitSHA(ref) {
		return strings.ToLower(ref), nil
	}

	cacheKey := fmt.Sprintf("%s/%s@%s", strings.ToLower(owner), strings.ToLower(repo), ref)

	r.mu.RLock()
	if sha, ok := r.cache[cacheKey]; ok {
		r.mu.RUnlock()
		return sha, nil
	}
	r.mu.RUnlock()

	sha, err := r.resolveFromAPI(ctx, owner, repo, ref)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[cacheKey] = sha
	r.mu.Unlock()

	return sha, nil
}

func (r *GitHubResolver) resolveFromAPI(ctx context.Context, owner, repo, ref string) (string, error) {
	// Normalize if caller passed refs/tags/... or refs/heads/...
	cleanRef := strings.TrimPrefix(ref, "refs/")

	var candidates []string
	if strings.HasPrefix(cleanRef, "tags/") || strings.HasPrefix(cleanRef, "heads/") {
		candidates = []string{cleanRef}
	} else {
		candidates = []string{
			"tags/" + cleanRef,
			"heads/" + cleanRef,
		}
	}

	var lastErr error
	for _, candidate := range candidates {
		gitRef, resp, err := r.client.Git.GetRef(ctx, owner, repo, candidate)
		if err != nil {
			lastErr = err
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue
			}
			return "", fmt.Errorf("querying git ref %s for %s/%s: %w", candidate, owner, repo, err)
		}
		if gitRef == nil || gitRef.Object == nil {
			continue
		}

		sha, err := r.dereferenceToCommit(ctx, owner, repo, gitRef.Object, 0)
		if err != nil {
			return "", err
		}
		return sha, nil
	}

	return "", fmt.Errorf("unable to resolve ref %q in %s/%s: %w", ref, owner, repo, lastErr)
}

// dereferenceToCommit follows annotated tag objects recursively until the underlying commit SHA is reached.
func (r *GitHubResolver) dereferenceToCommit(ctx context.Context, owner, repo string, obj *github.GitObject, depth int) (string, error) {
	if obj == nil {
		return "", errors.New("encountered nil git object while dereferencing")
	}
	if depth > maxTagDereferenceDepth {
		return "", fmt.Errorf("exceeded maximum tag dereference depth (%d) for %s/%s", maxTagDereferenceDepth, owner, repo)
	}

	objType := obj.GetType()
	objSHA := strings.ToLower(strings.TrimSpace(obj.GetSHA()))
	if objSHA == "" {
		return "", fmt.Errorf("empty SHA on git object of type %q in %s/%s", objType, owner, repo)
	}

	switch objType {
	case "commit":
		if !IsFullCommitSHA(objSHA) {
			return "", fmt.Errorf("resolved commit SHA %q is not a valid 40-char SHA", objSHA)
		}
		return objSHA, nil
	case "tag":
		tagObj, _, err := r.client.Git.GetTag(ctx, owner, repo, objSHA)
		if err != nil {
			return "", fmt.Errorf("dereferencing annotated tag %s in %s/%s: %w", objSHA, owner, repo, err)
		}
		if tagObj == nil || tagObj.Object == nil {
			return "", fmt.Errorf("annotated tag %s in %s/%s returned nil target object", objSHA, owner, repo)
		}
		return r.dereferenceToCommit(ctx, owner, repo, tagObj.Object, depth+1)
	default:
		return "", fmt.Errorf("unsupported git object type %q (sha %s) in %s/%s", objType, objSHA, owner, repo)
	}
}
