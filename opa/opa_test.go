package opa

import (
	"os"
	"regexp"
	"testing"

	"github.com/go-kit/log"
	"github.com/observatorium/api/rbac"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

func dummyCustomRegoFunction(logger log.Logger) func(*rego.Rego) {
	return rego.Function1(
		&rego.Function{
			Name: "isEmailAddress",
			Decl: types.NewFunction(types.Args(types.A), types.B)},
		func(_ rego.BuiltinContext, subject *ast.Term) (*ast.Term, error) {
			// Dummy check, allow only email-based subjects
			var validEmail = regexp.MustCompile(`^\S+@\S+\.\S+$`)
			return ast.BooleanTerm(validEmail.Match([]byte(subject.Value.String()))), nil
		})
}

func TestCustomRegoFunctions(t *testing.T) {
	onboardNewFunction("dummy-rego-function", dummyCustomRegoFunction)

	dir := t.TempDir()
	defer os.RemoveAll(dir)

	regoFile, err := os.CreateTemp(dir, "test.rego")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	defer os.Remove(regoFile.Name())

	regoLogic := `
package observatorium

import input

default allow = false

allow {
	isEmailAddress(input.subject)
}
`

	_, err = regoFile.Write([]byte(regoLogic))
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	authorizer, err := NewInProcessAuthorizer("data.observatorium.allow", []string{regoFile.Name()})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	t.Run("successful authorize with rego built-in function", func(t *testing.T) {
		_, isPermitted, data := authorizer.Authorize("example@example.com", []string{}, rbac.Write, "logs", "dummyTenant", "dummyTenantID", "")
		if len(data) != 0 {
			t.Fatalf("unexpected data: Got: %s, Wanted: %s", data, "")
		}

		if !isPermitted {
			t.Fatalf("unexpected permission response: Got: %t, Wanted: %t", isPermitted, true)
		}
	})

	t.Run("unsuccessful authorize with rego built-in function", func(t *testing.T) {
		_, isPermitted, data := authorizer.Authorize("dummySubject", []string{}, rbac.Write, "logs", "dummyTenant", "dummyTenantID", "")
		if len(data) != 0 {
			t.Fatalf("unexpected data: Got: %s, Wanted: %s", data, "")
		}
		if isPermitted {
			t.Fatalf("unexpected permission response: Got: %t, Wanted: %t", isPermitted, false)
		}
	})
}
