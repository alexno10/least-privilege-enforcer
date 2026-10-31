package gitpr

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"

	"github.com/alexno10/least-privilege-enforcer/internal/ast"
)

const (
	BranchPrefix = "security/least-privilege-enforcer"
	PRTitle      = "chore(security): enforce least-privilege permissions and pin GitHub Actions to commit SHAs"
)

// WorkflowChange represents a single remediated workflow file ready to be diffed or committed.
type WorkflowChange struct {
	// RepoRelativePath is the forward-slash path relative to the repository root (e.g., ".github/workflows/ci.yml").
	RepoRelativePath string
	OriginalBytes    []byte
	UpdatedBytes     []byte
	PinnedActions    []ast.PinnedAction
	JobPermissions   []ast.JobPermissionsRecord
}

// PRResult contains metadata about the created or updated Pull Request.
type PRResult struct {
	PRNumber   int
	HTMLURL    string
	BranchName string
	UpdatedExisting bool
}

// PRCreator manages unified diff rendering, branch/commit creation, and idempotent GitHub Pull Request management.
type PRCreator struct {
	client *github.Client
	nowFn  func() time.Time
}

// NewPRCreator creates a new PRCreator backed by the provided go-github client.
func NewPRCreator(client *github.Client) *PRCreator {
	return &PRCreator{
		client: client,
		nowFn:  time.Now,
	}
}

// CreateOrUpdatePR commits the modified workflow files via the GitHub Git Data API and opens or updates
// an idempotent Pull Request targeting the repository's default branch.
func (p *PRCreator) CreateOrUpdatePR(ctx context.Context, owner, repo string, changes []WorkflowChange) (*PRResult, error) {
	if len(changes) == 0 {
		return nil, nil
	}
	if p.client == nil {
		return nil, fmt.Errorf("github client is required to create or update a pull request")
	}

	// 1. Fetch repository metadata to determine the default branch.
	repoMeta, _, err := p.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, fmt.Errorf("fetching repository %s/%s: %w", owner, repo, err)
	}
	defaultBranch := repoMeta.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// 2. Get the base commit SHA and tree of the default branch.
	baseRef, _, err := p.client.Git.GetRef(ctx, owner, repo, "heads/"+defaultBranch)
	if err != nil {
		return nil, fmt.Errorf("getting base ref heads/%s: %w", defaultBranch, err)
	}
	baseSHA := baseRef.GetObject().GetSHA()

	// 3. Check for an existing open PR with head branch prefix `security/least-privilege-enforcer`.
	existingPR, err := p.findExistingOpenPR(ctx, owner, repo, defaultBranch)
	if err != nil {
		return nil, err
	}

	branchName := fmt.Sprintf("%s-%d", BranchPrefix, p.nowFn().UTC().Unix())
	if existingPR != nil && existingPR.GetHead() != nil && existingPR.GetHead().GetRef() != "" {
		branchName = existingPR.GetHead().GetRef()
	}

	// 4. Create a new Git tree with the updated workflow files based on baseSHA.
	var treeEntries []*github.TreeEntry
	for _, ch := range changes {
		relPath := filepath.ToSlash(ch.RepoRelativePath)
		treeEntries = append(treeEntries, &github.TreeEntry{
			Path:    github.String(relPath),
			Mode:    github.String("100644"),
			Type:    github.String("blob"),
			Content: github.String(string(ch.UpdatedBytes)),
		})
	}

	newTree, _, err := p.client.Git.CreateTree(ctx, owner, repo, baseSHA, treeEntries)
	if err != nil {
		return nil, fmt.Errorf("creating git tree: %w", err)
	}

	// 5. Create the commit on top of baseSHA.
	parentCommit := &github.Commit{SHA: github.String(baseSHA)}
	commitSpec := &github.Commit{
		Message: github.String(PRTitle),
		Tree:    newTree,
		Parents: []*github.Commit{parentCommit},
	}
	createdCommit, _, err := p.client.Git.CreateCommit(ctx, owner, repo, commitSpec, nil)
	if err != nil {
		return nil, fmt.Errorf("creating git commit: %w", err)
	}
	newCommitSHA := createdCommit.GetSHA()

	// 6. Create or update the branch reference.
	refSpec := &github.Reference{
		Ref: github.String("refs/heads/" + branchName),
		Object: &github.GitObject{
			SHA: github.String(newCommitSHA),
		},
	}
	if err := p.upsertBranchRef(ctx, owner, repo, branchName, refSpec); err != nil {
		return nil, err
	}

	// 7. Build the Markdown PR body.
	prBody := BuildPRBody(changes)

	// 8. Update existing PR or create a new PR.
	if existingPR != nil {
		updatedPR, _, err := p.client.PullRequests.Edit(ctx, owner, repo, existingPR.GetNumber(), &github.PullRequest{
			Title: github.String(PRTitle),
			Body:  github.String(prBody),
		})
		if err != nil {
			return nil, fmt.Errorf("updating existing PR #%d: %w", existingPR.GetNumber(), err)
		}
		return &PRResult{
			PRNumber:        updatedPR.GetNumber(),
			HTMLURL:         updatedPR.GetHTMLURL(),
			BranchName:      branchName,
			UpdatedExisting: true,
		}, nil
	}

	createdPR, _, err := p.client.PullRequests.Create(ctx, owner, repo, &github.NewPullRequest{
		Title: github.String(PRTitle),
		Head:  github.String(branchName),
		Base:  github.String(defaultBranch),
		Body:  github.String(prBody),
	})
	if err != nil {
		return nil, fmt.Errorf("creating pull request: %w", err)
	}

	return &PRResult{
		PRNumber:        createdPR.GetNumber(),
		HTMLURL:         createdPR.GetHTMLURL(),
		BranchName:      branchName,
		UpdatedExisting: false,
	}, nil
}

func (p *PRCreator) findExistingOpenPR(ctx context.Context, owner, repo, baseBranch string) (*github.PullRequest, error) {
	prs, _, err := p.client.PullRequests.List(ctx, owner, repo, &github.PullRequestListOptions{
		State: "open",
		Base:  baseBranch,
	})
	if err != nil {
		return nil, fmt.Errorf("listing open pull requests: %w", err)
	}
	for _, pr := range prs {
		if pr.GetHead() != nil && strings.HasPrefix(pr.GetHead().GetRef(), BranchPrefix) {
			return pr, nil
		}
	}
	return nil, nil
}

func (p *PRCreator) upsertBranchRef(ctx context.Context, owner, repo, branchName string, refSpec *github.Reference) error {
	_, resp, err := p.client.Git.GetRef(ctx, owner, repo, "heads/"+branchName)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			_, _, createErr := p.client.Git.CreateRef(ctx, owner, repo, refSpec)
			if createErr != nil {
				return fmt.Errorf("creating branch ref %s: %w", branchName, createErr)
			}
			return nil
		}
		return fmt.Errorf("checking branch ref %s: %w", branchName, err)
	}

	_, _, updateErr := p.client.Git.UpdateRef(ctx, owner, repo, refSpec, true)
	if updateErr != nil {
		return fmt.Errorf("updating branch ref %s: %w", branchName, updateErr)
	}
	return nil
}

// BuildPRBody generates a Markdown summary of all pinned actions and job-level permissions applied.
func BuildPRBody(changes []WorkflowChange) string {
	var sb strings.Builder

	sb.WriteString("## 🔒 Least-Privilege Enforcer Automated Remediation\n\n")
	sb.WriteString("This pull request hardens GitHub Actions workflows against supply-chain attacks by pinning mutable action references to full-length immutable commit SHAs and enforcing explicit least-privilege `GITHUB_TOKEN` permissions.\n\n")

	var allPinned []ast.PinnedAction
	var allPerms []ast.JobPermissionsRecord
	for _, ch := range changes {
		allPinned = append(allPinned, ch.PinnedActions...)
		allPerms = append(allPerms, ch.JobPermissions...)
	}

	sb.WriteString("### 📌 Pinned GitHub Actions\n\n")
	if len(allPinned) == 0 {
		sb.WriteString("_No mutable action references required pinning._\n\n")
	} else {
		sb.WriteString("| Action | Old Ref | Pinned SHA |\n")
		sb.WriteString("| :--- | :--- | :--- |\n")
		for _, pin := range allPinned {
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | `%s` |\n", pin.Action, pin.OldRef, pin.PinnedSHA))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("### 🛡️ Calculated Job Permissions\n\n")
	if len(allPerms) == 0 {
		sb.WriteString("_No job-level permission blocks required modification._\n")
	} else {
		sb.WriteString("| Workflow | Job | Calculated Permissions |\n")
		sb.WriteString("| :--- | :--- | :--- |\n")
		for _, jp := range allPerms {
			var formattedScopes []string
			for _, scope := range jp.Permissions.SortedScopes() {
				formattedScopes = append(formattedScopes, fmt.Sprintf("`%s: %s`", scope, jp.Permissions[scope]))
			}
			sb.WriteString(fmt.Sprintf("| `%s` | `%s` | %s |\n", jp.Workflow, jp.JobID, strings.Join(formattedScopes, ", ")))
		}
	}

	return sb.String()
}

// GenerateUnifiedDiff produces a unified diff representation between original and updated bytes for --dry-run output.
func GenerateUnifiedDiff(filePath string, oldBytes, newBytes []byte) string {
	if bytes.Equal(oldBytes, newBytes) {
		return ""
	}

	rel := filepath.ToSlash(filePath)
	oldLines := splitLines(string(oldBytes))
	newLines := splitLines(string(newBytes))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("--- a/%s\n", rel))
	sb.WriteString(fmt.Sprintf("+++ b/%s\n", rel))
	sb.WriteString(fmt.Sprintf("@@ -1,%d +1,%d @@\n", len(oldLines), len(newLines)))

	// Compute LCS table to emit clean unified diff lines (+, -, and context space).
	lcs := computeLCSMatrix(oldLines, newLines)
	i, j := 0, 0
	for i < len(oldLines) && j < len(newLines) {
		if oldLines[i] == newLines[j] {
			sb.WriteString(" " + oldLines[i] + "\n")
			i++
			j++
		} else if lcs[i+1][j] >= lcs[i][j+1] {
			sb.WriteString("-" + oldLines[i] + "\n")
			i++
		} else {
			sb.WriteString("+" + newLines[j] + "\n")
			j++
		}
	}
	for ; i < len(oldLines); i++ {
		sb.WriteString("-" + oldLines[i] + "\n")
	}
	for ; j < len(newLines); j++ {
		sb.WriteString("+" + newLines[j] + "\n")
	}

	return sb.String()
}

func splitLines(s string) []string {
	normalized := strings.ReplaceAll(s, "\r\n", "\n")
	normalized = strings.TrimSuffix(normalized, "\n")
	if normalized == "" {
		return nil
	}
	return strings.Split(normalized, "\n")
}

func computeLCSMatrix(a, b []string) [][]int {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := m - 1; i >= 0; i-- {
		for j := n - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = 1 + dp[i+1][j+1]
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	return dp
}
