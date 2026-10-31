package ast

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// WorkflowDocument wraps a parsed yaml.Node AST along with its source file path and original raw content.
type WorkflowDocument struct {
	FilePath string
	Original []byte
	Root     *yaml.Node
}

// ParseWorkflowFile reads and parses a GitHub Actions workflow YAML file into a yaml.Node AST.
func ParseWorkflowFile(path string) (*WorkflowDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading workflow file %s: %w", path, err)
	}
	doc, err := ParseWorkflowBytes(path, data)
	if err != nil {
		return nil, err
	}
	return doc, nil
}

// ParseWorkflowBytes parses raw YAML bytes into a WorkflowDocument while preserving all comments and structure.
func ParseWorkflowBytes(path string, data []byte) (*WorkflowDocument, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing YAML AST in %s: %w", path, err)
	}
	return &WorkflowDocument{
		FilePath: path,
		Original: append([]byte(nil), data...),
		Root:     &root,
	}, nil
}

// Serialize encodes the yaml.Node AST back into 2-space indented YAML bytes while preserving comments.
func (d *WorkflowDocument) Serialize() ([]byte, error) {
	if d == nil || d.Root == nil || len(d.Root.Content) == 0 {
		return nil, fmt.Errorf("cannot serialize empty workflow AST")
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d.Root); err != nil {
		_ = enc.Close()
		return nil, fmt.Errorf("encoding YAML AST for %s: %w", d.FilePath, err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("closing YAML encoder for %s: %w", d.FilePath, err)
	}

	return buf.Bytes(), nil
}

// DiscoverWorkflowFiles finds all *.yml and *.yaml files in the given workflows directory in deterministic order.
func DiscoverWorkflowFiles(workflowsDir string) ([]string, error) {
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		return nil, fmt.Errorf("reading workflows directory %s: %w", workflowsDir, err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yml" || ext == ".yaml" {
			files = append(files, filepath.Join(workflowsDir, entry.Name()))
		}
	}
	sort.Strings(files)
	return files, nil
}

// rootMapping returns the top-level MappingNode inside a DocumentNode.
func rootMapping(docNode *yaml.Node) (*yaml.Node, error) {
	if docNode == nil {
		return nil, fmt.Errorf("nil YAML node")
	}
	if docNode.Kind == yaml.DocumentNode {
		if len(docNode.Content) == 0 {
			return nil, fmt.Errorf("empty YAML document node")
		}
		docNode = docNode.Content[0]
	}
	if docNode.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected root MappingNode, got kind %v", docNode.Kind)
	}
	return docNode, nil
}

// findMapEntry locates a key in a MappingNode and returns its key node, value node, and index in Content.
func findMapEntry(mapNode *yaml.Node, key string) (*yaml.Node, *yaml.Node, int) {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil, nil, -1
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		v := mapNode.Content[i+1]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return k, v, i
		}
	}
	return nil, nil, -1
}

// insertMapEntryAfter inserts (newKey, newVal) into mapNode right after the first matching anchor key.
// If none of the anchor keys exist, it inserts before fallbackBeforeKey, or appends at the end.
func insertMapEntryAfter(mapNode *yaml.Node, newKey, newVal *yaml.Node, anchorKeys []string, fallbackBeforeKey string) {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return
	}

	insertIdx := -1
	for _, anchor := range anchorKeys {
		if _, _, idx := findMapEntry(mapNode, anchor); idx != -1 {
			insertIdx = idx + 2
			break
		}
	}

	if insertIdx == -1 && fallbackBeforeKey != "" {
		if _, _, idx := findMapEntry(mapNode, fallbackBeforeKey); idx != -1 {
			insertIdx = idx
		}
	}

	if insertIdx == -1 || insertIdx > len(mapNode.Content) {
		mapNode.Content = append(mapNode.Content, newKey, newVal)
		return
	}

	// Preserve comments that belong to the following key if yaml.v3 attached them as FootComment on the previous value.
	if insertIdx >= 2 && insertIdx < len(mapNode.Content) {
		prevVal := mapNode.Content[insertIdx-1]
		nextKey := mapNode.Content[insertIdx]
		if prevVal.FootComment != "" {
			if nextKey.HeadComment != "" {
				nextKey.HeadComment = prevVal.FootComment + "\n" + nextKey.HeadComment
			} else {
				nextKey.HeadComment = prevVal.FootComment
			}
			prevVal.FootComment = ""
		}
	}

	mapNode.Content = append(mapNode.Content[:insertIdx], append([]*yaml.Node{newKey, newVal}, mapNode.Content[insertIdx:]...)...)
}
