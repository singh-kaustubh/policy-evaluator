package expression

import (
	"context"
	"log"

	"github.com/expr-lang/expr"
	"github.com/pkg/errors"
	"github.com/policy-evaluator/pkg/datadog"
)

type BaseRule interface {
	GetExpression() string
	IsNotConclusive() bool
	GetActionNamesToTrigger() []string
}

type BasePolicy interface {
	GetRules() []BaseRule
	GetEssentialAttributesToTriggerActions() []string
}

type BaseActionOutput interface {
	GetIsSuccess() bool
	GetActionName() string
}

type DefaultOutput struct{}

func (d *DefaultOutput) GetIsSuccess() bool {
	return false
}

func (d *DefaultOutput) GetActionName() string {
	return "default"
}

type Action func(ip ...any) (BaseActionOutput, error)

type Attribute func(ip ...any) (any, error)

type policyEvalOutput struct {
	EventAttributes    any
	ApplicableRules    []string
	NonApplicableRules []string
	ActionsToTrigger   []string
	ActionOutputs      map[string]BaseActionOutput
	AppliedRules       []BaseRule
}

type defaultRule struct{}

func getDefaultRule() BaseRule {
	return &defaultRule{}
}

func (d *defaultRule) GetExpression() string {
	return ""
}

func (d *defaultRule) IsNotConclusive() bool {
	return false
}

func (d *defaultRule) GetActionNamesToTrigger() []string {
	return make([]string, 0)
}

func (p *policyEvalOutput) GetAppliedRules() []BaseRule {
	if p == nil {
		return []BaseRule{getDefaultRule()}
	}
	return p.AppliedRules
}

func ProcessPolicyEvalEvent(
	ctx context.Context,
	policy BasePolicy, // repo that will provide policy data
	env map[string]any,
) (*policyEvalOutput, error) {
	evalOut := &policyEvalOutput{
		ApplicableRules:    make([]string, 0),
		NonApplicableRules: make([]string, 0),
		ActionsToTrigger:   make([]string, 0),
		ActionOutputs:      make(map[string]BaseActionOutput, 0),
		AppliedRules:       make([]BaseRule, 0),
	}

	if policy == nil || len(policy.GetRules()) == 0 {
		return evalOut, nil
	}

	actionsExpressions := make([]string, 0)
	for _, rule := range policy.GetRules() {
		status, err := executeRuleExpression(ctx, rule.GetExpression(), env)
		if err != nil {
			return nil, err
		}

		if !status {
			evalOut.NonApplicableRules = append(evalOut.NonApplicableRules, rule.GetExpression())
			continue
		}
		evalOut.ApplicableRules = append(evalOut.ApplicableRules, rule.GetExpression())
		evalOut.AppliedRules = append(evalOut.AppliedRules, rule)
		actionsExpressions = append(actionsExpressions, rule.GetActionNamesToTrigger()...)

		if !rule.IsNotConclusive() {
			break
		}
	}

	evalOut.ActionsToTrigger = actionsExpressions

	for _, actionExpression := range actionsExpressions {
		out, err := executeActionExpression(ctx, actionExpression, env)
		if err != nil {
			return nil, err
		}
		evalOut.ActionOutputs[actionExpression] = out
		if !out.GetIsSuccess() {
			continue
		}
	}
	return evalOut, nil
}

func executeRuleExpression(ctx context.Context, expression string, e map[string]any) (bool, error) {
	program, err := expr.Compile(expression, expr.Env(e))
	if err != nil {
		return false, err
	}

	output, err := expr.Run(program, e)
	if err != nil {
		return false, err
	}
	result, ok := output.(bool)
	if !ok {
		datadog.NoticeError(ctx, errors.New("Invalid rule output type for expression: "+expression))
		return false, err
	}
	return result, nil
}

func executeActionExpression(ctx context.Context, expression string, e map[string]any) (BaseActionOutput, error) {
	program, err := expr.Compile(expression, expr.Env(e))
	if err != nil {
		return &DefaultOutput{}, err
	}

	output, err := expr.Run(program, e)
	if err != nil {
		return &DefaultOutput{}, err
	}
	result, ok := output.(BaseActionOutput)
	if !ok {
		log.Printf("Invalid action output type for expression: %s, environment: %v", expression, e)
		datadog.NoticeError(ctx, errors.New("Invalid action output type for expression: "+expression))
		return &DefaultOutput{}, err
	}
	return result, nil
}
