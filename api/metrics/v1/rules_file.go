package v1

import (
	"context"
	"errors"
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

// assumes the rules file is a prometheus rules file starting with "groups"

var RuleRepositoryNotImplementedErr = errors.New("Not implemented for rule repository.")

// NewRulesRepositoryFile implements RulesRepository interface with a file type, which is stateless and immutable
func NewRulesRepositoryFile(filepaths map[string]string) *RulesRepositoryFile {
	return &RulesRepositoryFile{Filepaths: filepaths}
}

type RulesRepositoryFile struct {
	Filepaths map[string]string
}

func (r *RulesRepositoryFile) ListRuleGroups(ctx context.Context, tenant string) (RuleGroups, error) {
	var groups RuleGroups

	filepath, ok := r.Filepaths[tenant]
	if !ok {
		return groups, nil
	}

	body, err := ioutil.ReadFile(filepath)

	if err != nil {
		return groups, err
	}

	if err := yaml.Unmarshal(body, &groups); err != nil {
		return groups, err
	}

	return groups, nil
}

func (r *RulesRepositoryFile) GetRules(ctx context.Context, tenant, name string) (RuleGroup, error) {
	var groups RuleGroups
	var group RuleGroup

	filepath, ok := r.Filepaths[tenant]
	if !ok {
		return group, nil
	}

	body, err := ioutil.ReadFile(filepath)

	if err != nil {
		return group, err
	}

	if err := yaml.Unmarshal(body, &groups); err != nil {
		return group, err
	}

	for _, g := range groups.Groups {
		if g.Name == name {
			return g, nil
		}
	}
	return group, nil
}

// immutable therefore nothing should happen
func (r *RulesRepositoryFile) UpdateRule(ctx context.Context, tenant string, name string, content []byte) error {
	return RuleRepositoryNotImplementedErr
}
