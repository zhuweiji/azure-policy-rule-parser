import json
import logging
import os
from pathlib import Path

import pytest

from src.main import parse_policy, parse_policy_rule
from src.main_parser import extract_types_from_policy

log = logging.getLogger(__name__)


TEST_DATA_DIR = Path(__file__).parent / 'extra_data'


def load_json_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)


def get_json_files():
    return sorted([os.path.join(TEST_DATA_DIR, f) for f in os.listdir(TEST_DATA_DIR) if f.endswith('.json')], reverse=True)


# @pytest.mark.parametrize('json_file', get_json_files())
# def test_function_with_json_files(json_file):
#     # set up
#     data = load_json_file(json_file)

#     # execution
#     result = parse_policy(data)
#     log.info(result)

#     # validation
#     assert result is not None


@pytest.mark.parametrize('json_file', get_json_files())
def test_parser_with_json_files(json_file):
    # set up
    data = load_json_file(json_file)

    rule = data['policyRule']

    # execution
    recurse_result = parse_policy(data)
    parse_result = extract_types_from_policy(rule)

    # validation
    recurse_result = recurse_result['included_services']
    assert sorted(recurse_result) == sorted(parse_result)
