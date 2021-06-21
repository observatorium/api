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
func (r *RulesRepositoryNop) ListRuleGroups(_ context.Context, _ string) (RuleGroups, error) {
	return RuleGroups{}, nil
}

// GetRules always returns an empty list.
func (r *RulesRepositoryNop) GetRules(_ context.Context, _, _ string) (RuleGroup, error) {
	var group RuleGroup
	return group, nil
}

// CreateRule always returns a not-implemented error.
func (r *RulesRepositoryNop) CreateRule(_ context.Context, _, _ string, _ int64, _ []byte) error {
	return ErrRuleRepositoryNotImplemented
}

// UpdateRule always returns a not-implemented error.
func (r *RulesRepositoryNop) UpdateRule(_ context.Context, _, _ string, _ int64, _ []byte) error {
	return ErrRuleRepositoryNotImplemented
}
