import json
from typing import List, Optional, Union

# AST Node Classes


class PolicyRule:
    def __init__(self, if_block, then_block):
        self.if_block = if_block
        self.then_block = then_block


class IfBlock:
    def __init__(self, condition_or_operator):
        self.condition_or_operator = condition_or_operator


class ThenBlock:
    def __init__(self, effect):
        self.effect = effect


class LogicalOperator:
    def __init__(self, operator: str, conditions: List[Union['Condition', 'LogicalOperator']]):
        self.operator = operator
        self.conditions = conditions


class Condition:
    def __init__(self, field: str, operator: str, value: Union[str, List[str], bool]):
        self.field = field
        self.operator = operator
        self.value = value

# Parser Class


class AzurePolicyRuleParser:
    def __init__(self, policy_json: Union[str, dict]):
        if isinstance(policy_json, str):
            policy_json = json.loads(policy_json)
        self.policy = policy_json
        self.current = None

    def parse(self) -> PolicyRule:
        if_block = self.parse_if_block()
        then_block = self.parse_then_block()
        return PolicyRule(if_block, then_block)

    def parse_if_block(self) -> IfBlock:
        if 'if' not in self.policy:
            raise ValueError("Missing 'if' block in policy rule")
        return IfBlock(self.parse_condition_or_operator(self.policy['if']))

    def parse_then_block(self) -> ThenBlock:
        if 'then' not in self.policy:
            raise ValueError("Missing 'then' block in policy rule")
        if 'effect' not in self.policy['then']:
            raise ValueError("Missing 'effect' in 'then' block")
        return ThenBlock(self.policy['then']['effect'])

    def parse_condition_or_operator(self, node) -> Union[Condition, LogicalOperator]:
        if 'field' in node:
            return self.parse_condition(node)
        elif 'not' in node:
            return LogicalOperator('not', [self.parse_condition_or_operator(node['not'])])
        elif 'allOf' in node:
            return LogicalOperator('allOf', [self.parse_condition_or_operator(c) for c in node['allOf']])
        elif 'anyOf' in node:
            return LogicalOperator('anyOf', [self.parse_condition_or_operator(c) for c in node['anyOf']])
        else:
            pass
            # raise ValueError(f"Unknown condition or operator: {node}")

    def parse_condition(self, node) -> Condition:
        field = node['field']
        operator, value = next((k, v) for k, v in node.items() if k != 'field')
        return Condition(field, operator, value)

# Type Extraction Visitor


class TypeExtractionVisitor:
    def __init__(self):
        self.types = set()

    def visit(self, node):
        method_name = f'visit_{type(node).__name__}'
        visit_method = getattr(self, method_name, self.generic_visit)
        return visit_method(node)

    def generic_visit(self, node):
        pass

    def visit_PolicyRule(self, node):
        self.visit(node.if_block)

    def visit_IfBlock(self, node):
        self.visit(node.condition_or_operator)

    def visit_LogicalOperator(self, node):
        for condition in node.conditions:
            self.visit(condition)

    def visit_Condition(self, node):
        if node.field == 'type':
            if node.operator == 'equals':
                self.types.add(node.value)
            elif node.operator == 'in':
                self.types.update(node.value)
            elif node.operator in ['like', 'match']:
                self.types.add(node.value)

    def get_types(self):
        return list(self.types)

# Usage example


def extract_types_from_policy(policy_json: str) -> List[str]:
    parser = AzurePolicyRuleParser(policy_json)
    ast = parser.parse()
    visitor = TypeExtractionVisitor()
    visitor.visit(ast)
    return visitor.get_types()


# Test the parser and type extraction
test_policy = '''
{
    "if": {
        "allOf": [
            {
                "not": {
                    "field": "tags",
                    "containsKey": "application"
                }
            },
            {
                "field": "type",
                "equals": "Microsoft.Storage/storageAccounts"
            }
        ]
    },
    "then": {
        "effect": "deny"
    }
}
'''
if __name__ == "__main__":
    types = extract_types_from_policy(test_policy)
    print(f"This policy applies to the following types: {types}")
