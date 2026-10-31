package ast

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alexno10/least-privilege-enforcer/internal/permissions"
	"github.com/alexno10/least-privilege-enforcer/internal/resolver"
)

// PinnedAction records a single mutable action reference that was pinned to a 40-char commit SHA.
type PinnedAction struct {
	Workflow  string
	JobID     string
	Action    string
	OldRef    string
	PinnedSHA string
}

// JobPermissionsRecord records the minimum permissions applied to a specific job in a workflow.
type JobPermissionsRecord struct {
	Workflow    string
	JobID       string
	Permissions permissions.PermissionSet
}

// MutationResult summarizes all AST mutations performed on a workflow document.
type MutationResult struct {
	WorkflowPath   string
	Modified       bool
	PinnedActions  []PinnedAction
	JobPermissions []JobPermissionsRecord
	UpdatedBytes   []byte
}

// MutatorOptions configures the behavior of the YAML AST mutator.
type MutatorOptions struct {
	Force bool
}

// Mutator pins mutable GitHub Action references to commit SHAs and injects least-privilege permissions into workflow ASTs.
type Mutator struct {
	Resolver  resolver.SHAResolver
	Extractor *permissions.Extractor
	Options   MutatorOptions
}

// NewMutator creates a new workflow AST Mutator.
func NewMutator(res resolver.SHAResolver, ext *permissions.Extractor, opts MutatorOptions) *Mutator {
	if ext == nil {
		ext = permissions.NewExtractor(nil)
	}
	return &Mutator{
		Resolver:  res,
		Extractor: ext,
		Options:   opts,
	}
}

// MutateWorkflow mutates doc.Root in-place to pin action SHAs and inject least-privilege permissions,
// returning the serialized output and structured telemetry for PR generation.
func (m *Mutator) MutateWorkflow(ctx context.Context, doc *WorkflowDocument) (*MutationResult, error) {
	if doc == nil || doc.Root == nil {
		return nil, fmt.Errorf("nil workflow document")
	}

	rootMap, err := rootMapping(doc.Root)
	if err != nil {
		return nil, fmt.Errorf("in %s: %w", doc.FilePath, err)
	}

	workflowName := filepath.Base(doc.FilePath)
	result := &MutationResult{
		WorkflowPath: doc.FilePath,
	}

	mutated := false

	// 1. Inspect and lock down top-level workflow permissions if missing, write-all, or --force is set.
	_, topPermVal, _ := findMapEntry(rootMap, "permissions")
	if shouldUpdatePermissions(topPermVal, m.Options.Force) {
		emptyPermMap := &yaml.Node{
			Kind:  yaml.MappingNode,
			Tag:   "!!map",
			Style: yaml.FlowStyle,
		}
		if topPermVal != nil {
			*topPermVal = *emptyPermMap
		} else {
			permKey := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: "permissions",
			}
			insertMapEntryAfter(rootMap, permKey, emptyPermMap, []string{"on", "name"}, "jobs")
		}
		mutated = true
	}

	// 2. Traverse jobs.<job_id>.
	_, jobsNode, _ := findMapEntry(rootMap, "jobs")
	if jobsNode != nil && jobsNode.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(jobsNode.Content); i += 2 {
			jobKeyNode := jobsNode.Content[i]
			jobValNode := jobsNode.Content[i+1]
			if jobValNode.Kind != yaml.MappingNode {
				continue
			}
			jobID := jobKeyNode.Value

			stepInputs, pinned, err := m.processJobSteps(ctx, workflowName, jobID, jobValNode)
			if err != nil {
				return nil, err
			}
			if len(pinned) > 0 {
				result.PinnedActions = append(result.PinnedActions, pinned...)
				mutated = true
			}

			// 3. Inject or update job-level permissions if missing, write-all, or --force is set.
			_, jobPermVal, _ := findMapEntry(jobValNode, "permissions")
			if shouldUpdatePermissions(jobPermVal, m.Options.Force) {
				inferred := m.Extractor.InferJobPermissions(ctx, stepInputs)
				permMapNode := buildPermissionsMappingNode(inferred)

				if jobPermVal != nil {
					*jobPermVal = *permMapNode
				} else {
					permKey := &yaml.Node{
						Kind:  yaml.ScalarNode,
						Tag:   "!!str",
						Value: "permissions",
					}
					insertMapEntryAfter(jobValNode, permKey, permMapNode, []string{"runs-on", "name", "environment"}, "steps")
				}

				result.JobPermissions = append(result.JobPermissions, JobPermissionsRecord{
					Workflow:    workflowName,
					JobID:       jobID,
					Permissions: inferred,
				})
				mutated = true
			}
		}
	}

	serialized, err := doc.Serialize()
	if err != nil {
		return nil, err
	}

	result.UpdatedBytes = serialized
	result.Modified = mutated && !bytes.Equal(doc.Original, serialized)
	return result, nil
}

func (m *Mutator) processJobSteps(ctx context.Context, workflowName, jobID string, jobValNode *yaml.Node) ([]permissions.StepInput, []PinnedAction, error) {
	var stepInputs []permissions.StepInput
	var pinned []PinnedAction

	_, stepsNode, _ := findMapEntry(jobValNode, "steps")
	if stepsNode == nil || stepsNode.Kind != yaml.SequenceNode {
		return stepInputs, pinned, nil
	}

	for _, stepNode := range stepsNode.Content {
		if stepNode.Kind != yaml.MappingNode {
			continue
		}

		_, usesNode, _ := findMapEntry(stepNode, "uses")
		_, withNode, _ := findMapEntry(stepNode, "with")
		_, runNode, _ := findMapEntry(stepNode, "run")

		stepIn := permissions.StepInput{
			With: extractScalarMap(withNode),
		}
		if runNode != nil && runNode.Kind == yaml.ScalarNode {
			stepIn.Run = runNode.Value
		}

		if usesNode != nil && usesNode.Kind == yaml.ScalarNode {
			rawUses := strings.TrimSpace(usesNode.Value)
			stepIn.Uses = rawUses

			if actionRef, ok := resolver.ParseActionUses(rawUses); ok {
				if resolver.IsFullCommitSHA(actionRef.Ref) {
					stepIn.ResolvedSHA = strings.ToLower(actionRef.Ref)
				} else if m.Resolver != nil {
					sha, err := m.Resolver.Resolve(ctx, actionRef.Owner, actionRef.Repo, actionRef.Ref)
					if err != nil {
						return nil, nil, fmt.Errorf("resolving %s in %s (job %s): %w", rawUses, workflowName, jobID, err)
					}
					usesNode.Value = actionRef.FormatPinned(sha)
					usesNode.LineComment = "# " + actionRef.Ref
					stepIn.ResolvedSHA = sha

					pinned = append(pinned, PinnedAction{
						Workflow:  workflowName,
						JobID:     jobID,
						Action:    actionRef.ActionName(),
						OldRef:    actionRef.Ref,
						PinnedSHA: sha,
					})
				}
			}
		}

		stepInputs = append(stepInputs, stepIn)
	}

	return stepInputs, pinned, nil
}

func shouldUpdatePermissions(permValNode *yaml.Node, force bool) bool {
	if force || permValNode == nil {
		return true
	}
	if permValNode.Kind == yaml.ScalarNode {
		val := strings.ToLower(strings.TrimSpace(permValNode.Value))
		if val == "write-all" || val == "" {
			return true
		}
	}
	return false
}

func buildPermissionsMappingNode(perms permissions.PermissionSet) *yaml.Node {
	mapNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Tag:  "!!map",
	}
	for _, scope := range perms.SortedScopes() {
		level := perms[scope]
		mapNode.Content = append(mapNode.Content,
			&yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: scope,
			},
			&yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   "!!str",
				Value: string(level),
			},
		)
	}
	return mapNode
}

func extractScalarMap(mapNode *yaml.Node) map[string]string {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}
	out := make(map[string]string, len(mapNode.Content)/2)
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		v := mapNode.Content[i+1]
		if k.Kind == yaml.ScalarNode && v.Kind == yaml.ScalarNode {
			out[strings.ToLower(strings.TrimSpace(k.Value))] = strings.TrimSpace(v.Value)
		}
	}
	return out
}
