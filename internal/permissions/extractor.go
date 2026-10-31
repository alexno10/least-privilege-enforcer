package permissions

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/google/go-github/v62/github"
	"gopkg.in/yaml.v3"

	"github.com/alexno10/least-privilege-enforcer/internal/resolver"
)

// validPermissionScopes enumerates the recognized GitHub Actions GITHUB_TOKEN permission scopes.
var validPermissionScopes = map[string]bool{
	"actions":            true,
	"attestations":       true,
	"checks":             true,
	"contents":           true,
	"deployments":        true,
	"discussions":        true,
	"id-token":           true,
	"issues":             true,
	"models":             true,
	"packages":           true,
	"pages":              true,
	"pull-requests":      true,
	"repository-projects": true,
	"security-events":    true,
	"statuses":           true,
}

var annotatedPermRegex = regexp.MustCompile(`(?i)\b(actions|attestations|checks|contents|deployments|discussions|id-token|issues|models|packages|pages|pull-requests|repository-projects|security-events|statuses)\s*:\s*(read|write)\b`)

// StepInput represents the relevant attributes of a workflow step for permission inference.
type StepInput struct {
	Uses        string
	ResolvedSHA string
	With        map[string]string
	Run         string
}

// Extractor implements the 3-tier permission inference strategy:
// 1. Upstream action.yml / reusable workflow inspection via GitHub API
// 2. Curated knowledge base of common GitHub Actions
// 3. Static shell command analysis of `run:` blocks
type Extractor struct {
	client *github.Client
	mu     sync.RWMutex
	cache  map[string]PermissionSet
}

// NewExtractor creates a new Extractor backed by the given GitHub client.
func NewExtractor(client *github.Client) *Extractor {
	return &Extractor{
		client: client,
		cache:  make(map[string]PermissionSet),
	}
}

// InferJobPermissions calculates the minimum required permissions across all steps in a job
// using the lattice model (none < read < write), falling back to `contents: read` if nothing matches.
func (e *Extractor) InferJobPermissions(ctx context.Context, steps []StepInput) PermissionSet {
	jobPerms := NewPermissionSet()

	for _, step := range steps {
		if strings.TrimSpace(step.Uses) != "" {
			stepPerms := e.InferActionPermissions(ctx, step.Uses, step.ResolvedSHA, step.With)
			jobPerms.Merge(stepPerms)
		}
		if strings.TrimSpace(step.Run) != "" {
			runPerms := AnalyzeRunScript(step.Run)
			jobPerms.Merge(runPerms)
		}
	}

	return jobPerms.WithDefaultFallback()
}

// InferActionPermissions resolves permissions for a single `uses:` action reference using Tier 1 and Tier 2.
func (e *Extractor) InferActionPermissions(ctx context.Context, uses, resolvedSHA string, withParams map[string]string) PermissionSet {
	result := NewPermissionSet()

	actionRef, ok := resolver.ParseActionUses(uses)
	if !ok {
		return result
	}

	refToFetch := strings.TrimSpace(resolvedSHA)
	if refToFetch == "" {
		refToFetch = actionRef.Ref
	}

	// Tier 1: Fetch and inspect upstream action.yml / reusable workflow if a GitHub client is configured.
	if e != nil && e.client != nil && refToFetch != "" {
		if upstreamPerms, err := e.FetchUpstreamPermissions(ctx, actionRef.Owner, actionRef.Repo, actionRef.Subpath, refToFetch); err == nil && len(upstreamPerms) > 0 {
			result.Merge(upstreamPerms)
		}
	}

	// Tier 2: Check curated knowledge base.
	if curatedPerms, found := LookupCuratedAction(actionRef.ActionName(), withParams); found {
		result.Merge(curatedPerms)
	}

	return result
}

// FetchUpstreamPermissions fetches action.yml, action.yaml, or a reusable workflow YAML at the target ref
// and extracts any declared or annotated permissions.
func (e *Extractor) FetchUpstreamPermissions(ctx context.Context, owner, repo, subpath, ref string) (PermissionSet, error) {
	cacheKey := fmt.Sprintf("%s/%s/%s@%s", strings.ToLower(owner), strings.ToLower(repo), subpath, ref)

	e.mu.RLock()
	if cached, ok := e.cache[cacheKey]; ok {
		e.mu.RUnlock()
		return cached.Clone(), nil
	}
	e.mu.RUnlock()

	candidatePaths := buildCandidateMetadataPaths(subpath)
	var rawContent string
	var lastErr error

	for _, path := range candidatePaths {
		fileContent, _, resp, err := e.client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{
			Ref: ref,
		})
		if err != nil {
			lastErr = err
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				continue
			}
			return nil, fmt.Errorf("fetching %s from %s/%s@%s: %w", path, owner, repo, ref, err)
		}
		if fileContent == nil {
			continue
		}
		decoded, err := fileContent.GetContent()
		if err != nil {
			lastErr = err
			continue
		}
		rawContent = decoded
		break
	}

	if rawContent == "" {
		return nil, fmt.Errorf("no upstream action metadata found for %s/%s (%s) at %s: %w", owner, repo, subpath, ref, lastErr)
	}

	perms := ParseUpstreamMetadataYAML(rawContent)

	e.mu.Lock()
	e.cache[cacheKey] = perms.Clone()
	e.mu.Unlock()

	return perms, nil
}

func buildCandidateMetadataPaths(subpath string) []string {
	clean := strings.Trim(subpath, "/")
	if clean == "" {
		return []string{"action.yml", "action.yaml"}
	}
	if strings.HasSuffix(clean, ".yml") || strings.HasSuffix(clean, ".yaml") {
		return []string{clean}
	}
	return []string{
		clean + "/action.yml",
		clean + "/action.yaml",
	}
}

// ParseUpstreamMetadataYAML extracts permissions from an upstream action.yml or reusable workflow YAML string.
func ParseUpstreamMetadataYAML(content string) PermissionSet {
	perms := NewPermissionSet()
	if strings.TrimSpace(content) == "" {
		return perms
	}

	var doc struct {
		Description string      `yaml:"description"`
		Permissions interface{} `yaml:"permissions"`
		Inputs      map[string]struct {
			Description string `yaml:"description"`
		} `yaml:"inputs"`
		Jobs map[string]struct {
			Permissions interface{} `yaml:"permissions"`
		} `yaml:"jobs"`
	}

	if err := yaml.Unmarshal([]byte(content), &doc); err == nil {
		// 1. Explicit top-level permissions block (custom action.yml field or reusable workflow).
		parseRawPermissionsField(doc.Permissions, perms)

		// 2. Reusable workflow job-level permissions blocks.
		for _, job := range doc.Jobs {
			parseRawPermissionsField(job.Permissions, perms)
		}

		// 3. Structured permission hints in action description or input descriptions.
		extractAnnotatedPermissionsFromText(doc.Description, perms)
		for _, input := range doc.Inputs {
			extractAnnotatedPermissionsFromText(input.Description, perms)
		}
	}

	// 4. Also scan YAML comments for annotated permission declarations (e.g., `# permissions: contents: write`).
	for _, line := range strings.Split(content, "\n") {
		if idx := strings.Index(line, "#"); idx != -1 {
			extractAnnotatedPermissionsFromText(line[idx+1:], perms)
		}
	}

	return perms
}

func parseRawPermissionsField(raw interface{}, target PermissionSet) {
	if raw == nil {
		return
	}
	switch v := raw.(type) {
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "read-all":
			target.Add("contents", AccessRead)
		case "write-all":
			target.Add("contents", AccessWrite)
		}
	case map[string]interface{}:
		for k, val := range v {
			scope := strings.ToLower(strings.TrimSpace(k))
			if !validPermissionScopes[scope] {
				continue
			}
			levelStr, ok := val.(string)
			if !ok {
				continue
			}
			switch strings.ToLower(strings.TrimSpace(levelStr)) {
			case "read":
				target.Add(scope, AccessRead)
			case "write":
				target.Add(scope, AccessWrite)
			}
		}
	}
}

func extractAnnotatedPermissionsFromText(text string, target PermissionSet) {
	if strings.TrimSpace(text) == "" {
		return
	}
	matches := annotatedPermRegex.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) == 3 {
			scope := strings.ToLower(m[1])
			level := AccessLevel(strings.ToLower(m[2]))
			if validPermissionScopes[scope] {
				target.Add(scope, level)
			}
		}
	}
}
