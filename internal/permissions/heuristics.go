package permissions

import (
	"regexp"
	"sort"
	"strings"
)

// AccessLevel represents the permission level for a GitHub token scope.
type AccessLevel string

const (
	AccessNone  AccessLevel = "none"
	AccessRead  AccessLevel = "read"
	AccessWrite AccessLevel = "write"
)

func accessRank(level AccessLevel) int {
	switch level {
	case AccessWrite:
		return 2
	case AccessRead:
		return 1
	default:
		return 0
	}
}

// PermissionSet maps GitHub token scopes (e.g., "contents", "pull-requests") to their minimum required AccessLevel.
type PermissionSet map[string]AccessLevel

// NewPermissionSet creates an empty PermissionSet.
func NewPermissionSet() PermissionSet {
	return make(PermissionSet)
}

// Add sets or upgrades the access level for a scope according to the lattice: none < read < write.
func (p PermissionSet) Add(scope string, level AccessLevel) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	if scope == "" || level == "" || level == AccessNone {
		return
	}
	current, exists := p[scope]
	if !exists || accessRank(level) > accessRank(current) {
		p[scope] = level
	}
}

// Merge combines another PermissionSet into p using the lattice model (none < read < write).
func (p PermissionSet) Merge(other PermissionSet) {
	for scope, level := range other {
		p.Add(scope, level)
	}
}

// Clone returns a deep copy of the PermissionSet.
func (p PermissionSet) Clone() PermissionSet {
	out := NewPermissionSet()
	out.Merge(p)
	return out
}

// WithDefaultFallback returns a copy of the PermissionSet, defaulting to `contents: read` if empty.
func (p PermissionSet) WithDefaultFallback() PermissionSet {
	out := p.Clone()
	if len(out) == 0 {
		out.Add("contents", AccessRead)
	}
	return out
}

// SortedScopes returns all permission scope keys in deterministic alphabetical order.
func (p PermissionSet) SortedScopes() []string {
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// knownActionHeuristics holds the curated knowledge base of common GitHub Actions and their minimum permissions.
var knownActionHeuristics = map[string]PermissionSet{
	"actions/checkout": {
		"contents": AccessRead,
	},
	"github/codeql-action/upload-sarif": {
		"security-events": AccessWrite,
		"actions":         AccessRead,
		"contents":        AccessRead,
	},
	"github/codeql-action/init": {
		"security-events": AccessWrite,
		"actions":         AccessRead,
		"contents":        AccessRead,
	},
	"github/codeql-action/analyze": {
		"security-events": AccessWrite,
		"actions":         AccessRead,
		"contents":        AccessRead,
	},
	"actions/cache": {
		"contents": AccessRead,
	},
	"softprops/action-gh-release": {
		"contents": AccessWrite,
	},
	"peter-evans/create-pull-request": {
		"contents":      AccessWrite,
		"pull-requests": AccessWrite,
	},
	"alexno10/least-privilege-enforcer": {
		"contents":      AccessWrite,
		"pull-requests": AccessWrite,
	},
	"docker/login-action": {
		"packages": AccessWrite,
		"contents": AccessRead,
	},
	"docker/build-push-action": {
		"packages": AccessWrite,
		"contents": AccessRead,
	},
	"actions/setup-go": {
		"contents": AccessRead,
	},
	"actions/setup-node": {
		"contents": AccessRead,
	},
	"actions/setup-python": {
		"contents": AccessRead,
	},
	"actions/upload-artifact": {
		"contents": AccessRead,
	},
	"actions/download-artifact": {
		"contents": AccessRead,
	},
}

// LookupCuratedAction checks the built-in curated knowledge base for a given action name
// (e.g., "actions/checkout" or "github/codeql-action/upload-sarif") and optional step `with:` parameters.
func LookupCuratedAction(actionName string, withParams map[string]string) (PermissionSet, bool) {
	normalized := strings.ToLower(strings.TrimSpace(actionName))

	// Special handling for docker actions when withParams are provided:
	// If a non-ghcr.io registry is explicitly configured on docker/login-action, only contents: read is needed.
	if normalized == "docker/login-action" && len(withParams) > 0 {
		if reg, ok := withParams["registry"]; ok && strings.TrimSpace(reg) != "" && !strings.Contains(strings.ToLower(reg), "ghcr.io") {
			return PermissionSet{"contents": AccessRead}, true
		}
	}

	if perms, ok := knownActionHeuristics[normalized]; ok {
		return perms.Clone(), true
	}
	return nil, false
}

type shellRule struct {
	pattern *regexp.Regexp
	perms   PermissionSet
}

var shellAnalyzerRules = []shellRule{
	{
		pattern: regexp.MustCompile(`(?m)\b(?:git\s+push|gh\s+release\s+create)\b`),
		perms: PermissionSet{
			"contents": AccessWrite,
		},
	},
	{
		pattern: regexp.MustCompile(`(?m)\bgh\s+pr\s+(?:create|comment|edit|merge|close|ready|review)\b`),
		perms: PermissionSet{
			"pull-requests": AccessWrite,
		},
	},
	{
		pattern: regexp.MustCompile(`(?m)\bgh\s+issue\b`),
		perms: PermissionSet{
			"issues": AccessWrite,
		},
	},
}

// AnalyzeRunScript scans a shell `run:` script block for CLI commands that require elevated GITHUB_TOKEN permissions.
func AnalyzeRunScript(script string) PermissionSet {
	result := NewPermissionSet()
	if strings.TrimSpace(script) == "" {
		return result
	}

	for _, rule := range shellAnalyzerRules {
		if rule.pattern.MatchString(script) {
			result.Merge(rule.perms)
		}
	}
	return result
}
