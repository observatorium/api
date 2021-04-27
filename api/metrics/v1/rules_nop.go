package v1

import (
	"context"
)

type RulesRepositoryNop struct {
}

func (r *RulesRepositoryNop) ListRuleGroups(ctx context.Context, tenant string) (RuleGroups, error) {
	var groups RuleGroups
	return groups, nil
}

func (r *RulesRepositoryNop) GetRules(ctx context.Context, tenant, name string) (RuleGroup, error) {
	var group RuleGroup
	return group, nil
}

func (r *RulesRepositoryNop) UpdateRule(ctx context.Context, tenant string, name string, content []byte) error {
	return RuleRepositoryNotImplementedErr
}
