package v1

import (
	"context"
	"database/sql"

	"github.com/prometheus/prometheus/pkg/rulefmt"
	"gopkg.in/yaml.v3"
)

// NewRulesRepository implements RulesRepository interface with Postgres
// which the RulesAPI requires.
func NewRulesRepository(db *sql.DB) *RulesRepositoryPostgres {
	return &RulesRepositoryPostgres{db: db}
}

// RulesRepositoryPostgres the actual implementation of RulesRepository for Postgres.
type RulesRepositoryPostgres struct {
	db *sql.DB
}

func (r *RulesRepositoryPostgres) ListRuleGroups(ctx context.Context, tenant string) (RuleGroups, error) {
	var groups RuleGroups

	query := `SELECT name, rules FROM metrics_rules WHERE tenant = $1 ORDER BY name ASC`
	rows, err := r.db.QueryContext(ctx, query, tenant)
	if err != nil {
		return groups, err
	}
	defer rows.Close()

	for rows.Next() {
		var name, r string
		if err := rows.Scan(&name, &r); err != nil {
			return groups, err
		}

		var rules []rulefmt.Rule
		if err := yaml.Unmarshal([]byte(r), &rules); err != nil {
			return groups, err
		}

		groups.Groups = append(groups.Groups, RuleGroup{
			Name:     name,
			Interval: 0,
			Rules:    rules,
		})
	}
	if err := rows.Close(); err != nil {
		return groups, err
	}
	if err := rows.Err(); err != nil {
		return groups, err
	}

	return groups, nil
}

func (r *RulesRepositoryPostgres) GetRules(ctx context.Context, tenant, name string) (RuleGroup, error) {
	query := `SELECT rules FROM metrics_rules WHERE tenant = $1 AND name = $2 LIMIT 1;`

	var rulesYAML string
	err := r.db.QueryRowContext(ctx, query, tenant, name).Scan(&rulesYAML)
	if err == sql.ErrNoRows {
		return RuleGroup{}, RuleNotFoundErr
	}
	if err != nil {
		return RuleGroup{}, err
	}

	var rules []rulefmt.Rule
	if err := yaml.Unmarshal([]byte(rulesYAML), &rules); err != nil {
		return RuleGroup{}, err
	}

	return RuleGroup{
		Name:  name,
		Rules: rules,
	}, nil
}

func (r *RulesRepositoryPostgres) UpdateRule(ctx context.Context, tenant string, name string, content []byte) error {
	query := `UPDATE metrics_rules SET rules = $3 WHERE tenant = $1 AND name = $2`

	result, err := r.db.ExecContext(ctx, query, tenant, name, content)
	if err != nil {
		return err
	}
	affectedRows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affectedRows != 1 {
		return RuleNotFoundErr
	}

	return nil
}
