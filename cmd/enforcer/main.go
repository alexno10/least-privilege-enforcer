package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-github/v62/github"
	"golang.org/x/oauth2"

	"github.com/alexno10/least-privilege-enforcer/internal/ast"
	"github.com/alexno10/least-privilege-enforcer/internal/gitpr"
	"github.com/alexno10/least-privilege-enforcer/internal/permissions"
	"github.com/alexno10/least-privilege-enforcer/internal/resolver"
)

// Config holds the runtime configuration resolved from CLI flags and GitHub Action INPUT_* env vars.
type Config struct {
	WorkflowsDir string
	DryRun       bool
	Force        bool
	GitHubToken  string
	Repo         string
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing configuration: %v\n", err)
		os.Exit(2)
	}

	if err := run(context.Background(), cfg, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func parseConfig(args []string, getenv func(string) string) (*Config, error) {
	fs := flag.NewFlagSet("least-privilege-enforcer", flag.ContinueOnError)

	defaultWorkflowsDir := firstNonEmpty(getenv("INPUT_WORKFLOWS_DIR"), getenv("INPUT_WORKFLOWS-DIR"), ".github/workflows")
	defaultDryRun := parseBoolEnv(firstNonEmpty(getenv("INPUT_DRY_RUN"), getenv("INPUT_DRY-RUN")), false)
	defaultForce := parseBoolEnv(getenv("INPUT_FORCE"), false)
	defaultToken := firstNonEmpty(getenv("INPUT_GITHUB_TOKEN"), getenv("INPUT_GITHUB-TOKEN"), getenv("GITHUB_TOKEN"))
	defaultRepo := firstNonEmpty(getenv("INPUT_REPO"), getenv("GITHUB_REPOSITORY"))

	workflowsDir := fs.String("workflows-dir", defaultWorkflowsDir, "Directory containing GitHub Actions workflow YAML files")
	dryRun := fs.Bool("dry-run", defaultDryRun, "Print unified diffs to stdout without mutating files or creating a PR")
	force := fs.Bool("force", defaultForce, "Overwrite existing non-write-all permission blocks")
	githubToken := fs.String("github-token", defaultToken, "GitHub token for API authentication and PR creation")
	repo := fs.String("repo", defaultRepo, "Target GitHub repository in owner/repo format")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	return &Config{
		WorkflowsDir: strings.TrimSpace(*workflowsDir),
		DryRun:       *dryRun,
		Force:        *force,
		GitHubToken:  strings.TrimSpace(*githubToken),
		Repo:         strings.TrimSpace(*repo),
	}, nil
}

func run(ctx context.Context, cfg *Config, stdout, stderr io.Writer) error {
	files, err := ast.DiscoverWorkflowFiles(cfg.WorkflowsDir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		fmt.Fprintf(stdout, "No workflow files (*.yml, *.yaml) found in %s\n", cfg.WorkflowsDir)
		return nil
	}

	ghClient := newGitHubClient(ctx, cfg.GitHubToken)
	shaResolver := resolver.NewGitHubResolver(ghClient)
	permExtractor := permissions.NewExtractor(ghClient)
	mutator := ast.NewMutator(shaResolver, permExtractor, ast.MutatorOptions{
		Force: cfg.Force,
	})

	var changes []gitpr.WorkflowChange

	for _, file := range files {
		doc, err := ast.ParseWorkflowFile(file)
		if err != nil {
			return err
		}

		res, err := mutator.MutateWorkflow(ctx, doc)
		if err != nil {
			return err
		}
		if !res.Modified {
			continue
		}

		relPath := normalizeRepoRelativePath(file)
		changes = append(changes, gitpr.WorkflowChange{
			RepoRelativePath: relPath,
			OriginalBytes:    doc.Original,
			UpdatedBytes:     res.UpdatedBytes,
			PinnedActions:    res.PinnedActions,
			JobPermissions:   res.JobPermissions,
		})
	}

	if len(changes) == 0 {
		fmt.Fprintln(stdout, "All workflow files already adhere to least-privilege permissions and immutable SHA pinning.")
		return nil
	}

	if cfg.DryRun {
		for _, ch := range changes {
			diff := gitpr.GenerateUnifiedDiff(ch.RepoRelativePath, ch.OriginalBytes, ch.UpdatedBytes)
			fmt.Fprint(stdout, diff)
		}
		return nil
	}

	// Write updated workflow files in-place on disk.
	for i, file := range files {
		for _, ch := range changes {
			if normalizeRepoRelativePath(file) == ch.RepoRelativePath {
				if err := os.WriteFile(file, changes[iIfMatch(file, changes)].UpdatedBytes, 0o644); err != nil {
					return fmt.Errorf("writing remediated workflow %s: %w", file, err)
				}
				break
			}
		}
		_ = i
	}

	// If --repo is provided, commit changes and open/update the automated Pull Request via GitHub API.
	if cfg.Repo != "" {
		owner, repoName, err := splitOwnerRepo(cfg.Repo)
		if err != nil {
			return err
		}
		if cfg.GitHubToken == "" {
			return fmt.Errorf("--github-token (or GITHUB_TOKEN) is required when --repo (%s) is specified without --dry-run", cfg.Repo)
		}

		creator := gitpr.NewPRCreator(ghClient)
		prRes, err := creator.CreateOrUpdatePR(ctx, owner, repoName, changes)
		if err != nil {
			return err
		}
		if prRes != nil {
			actionWord := "Created"
			if prRes.UpdatedExisting {
				actionWord = "Updated existing"
			}
			fmt.Fprintf(stdout, "%s Pull Request #%d (%s) on branch %s\n", actionWord, prRes.PRNumber, prRes.HTMLURL, prRes.BranchName)
			writeGitHubActionsOutput(prRes, len(changes), stderr)
		}
	} else {
		fmt.Fprintf(stdout, "Remediated %d workflow file(s) in-place.\n", len(changes))
	}

	return nil
}

func iIfMatch(file string, changes []gitpr.WorkflowChange) int {
	norm := normalizeRepoRelativePath(file)
	for idx, ch := range changes {
		if ch.RepoRelativePath == norm {
			return idx
		}
	}
	return 0
}

func normalizeRepoRelativePath(file string) string {
	slashed := filepath.ToSlash(file)
	if idx := strings.Index(slashed, ".github/workflows/"); idx != -1 {
		return slashed[idx:]
	}
	return strings.TrimPrefix(slashed, "./")
}

func splitOwnerRepo(repo string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(repo), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid --repo value %q: expected owner/repo format", repo)
	}
	return parts[0], parts[1], nil
}

func newGitHubClient(ctx context.Context, token string) *github.Client {
	var httpClient *http.Client
	if strings.TrimSpace(token) != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: strings.TrimSpace(token)})
		httpClient = oauth2.NewClient(ctx, ts)
	}
	return github.NewClient(httpClient)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func parseBoolEnv(val string, fallback bool) bool {
	if val == "" {
		return fallback
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return fallback
	}
	return b
}

func writeGitHubActionsOutput(prRes *gitpr.PRResult, modifiedCount int, stderr io.Writer) {
	outputPath := os.Getenv("GITHUB_OUTPUT")
	if strings.TrimSpace(outputPath) == "" || prRes == nil {
		return
	}
	f, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(stderr, "Warning: failed to open GITHUB_OUTPUT (%s): %v\n", outputPath, err)
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "pr-number=%d\n", prRes.PRNumber)
	fmt.Fprintf(f, "pr-url=%s\n", prRes.HTMLURL)
	fmt.Fprintf(f, "branch=%s\n", prRes.BranchName)
	fmt.Fprintf(f, "modified-workflows=%d\n", modifiedCount)
}
