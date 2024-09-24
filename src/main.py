import json
import logging
from typing import Dict, List, Tuple

logging.basicConfig(
    format='%(name)s-%(levelname)s|%(lineno)d:  %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


def parse_policy(policy: Dict):
    result = {}

    policy_id = policy.get('id')
    policy_type = policy.get('type')
    policy_name = policy.get('name')

    # azure portal has policyrules in properties.policyRule but az cli output has it as just policyRule
    policy_rule = policy.get('policyRule')
    if not policy_rule:
        raise ValueError('Policy must have Policy Rule')

    included_services, excluded_services = parse_policy_rule(policy_rule)
    result['included_services'] = included_services
    result['excluded_services'] = excluded_services

    return result


def parse_policy_rule(rule: Dict) -> Tuple[List[str], List[str]]:
    included_services = set()
    excluded_services = set()

    def parse_condition(condition: Dict, negate: bool = False):
        if "field" in condition and condition["field"] == "type":
            service = condition.get("equals") or \
                condition.get("in", []) or \
                condition.get("like")

            if isinstance(service, str):
                service = [service]
            if negate:
                excluded_services.update(service)
            else:
                included_services.update(service)

    def parse_logical_operator(operator: Dict, negate: bool = False):
        if "not" in operator:
            parse_logical_operator(operator["not"], not negate)
        elif "allOf" in operator or "anyOf" in operator:
            conditions = operator.get("allOf") or operator.get("anyOf")
            for condition in conditions:
                parse_rule(condition, negate)
        else:
            parse_condition(operator, negate)

    def parse_rule(rule: Dict, negate: bool = False):
        if "if" in rule:
            parse_rule(rule["if"], negate)
        elif "not" in rule:
            parse_rule(rule["not"], not negate)
        elif "allOf" in rule or "anyOf" in rule:
            parse_logical_operator(rule, negate)
        else:
            parse_condition(rule, negate)

    parse_rule(rule)
    return list(included_services), list(excluded_services)


if __name__ == "__main__":

    # Example usage
    policy_rule = {
        "if": {
            "allOf": [
                {
                    "not": {
                        "field": "type",
                        "equals": "Microsoft.Storage/storageAccounts"
                    }
                },
                {
                    "field": "type",
                    "equals": "Microsoft.Compute/virtualMachines"
                }
            ]
        },
        "then": {
            "effect": "audit"
        }
    }

    included, excluded = parse_policy_rule(policy_rule)
    print("Included services:", included)
    print("Excluded services:", excluded)
