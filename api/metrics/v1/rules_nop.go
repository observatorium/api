package v1

import (
	"context"
)

// RulesRepositoryNop implements the RulesRepository interface by doing nothing.
type RulesRepositoryNop struct {
}

// Statically check that the nop rules repository implements the RulesRepository interface.
var _ RulesRepository = (*RulesRepositoryNop)(nil)

// ListRuleGroups always returns an empty list.
func (r *RulesRepositoryNop) ListRuleGroups(ctx context.Context, tenant string) (RuleGroups, error) {
	var groups RuleGroups
	return groups, nil
}

// GetRules always returns an empty list.
func (r *RulesRepositoryNop) GetRules(ctx context.Context, tenant, name string) (RuleGroup, error) {
	var group RuleGroup
	return group, nil
}

// UpdateRule always returns a not-implemented error.
func (r *RulesRepositoryNop) UpdateRule(ctx context.Context, tenant string, name string, content []byte) error {
	return ErrRuleRepositoryNotImplemented
}
