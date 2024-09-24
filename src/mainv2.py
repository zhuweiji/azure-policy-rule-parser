import json
import logging

from src.main import parse_policy

logging.basicConfig(
    format='%(name)s-%(levelname)s|%(lineno)d:  %(message)s', level=logging.INFO)
log = logging.getLogger(__name__)


f = r'D:\projects\testbed\azure-policy-rule-parser\src\tests\0b7ef78e-a035-4f23-b9bd-aff122a1b1cf.json'


def load_json_file(filename):
    with open(filename, 'r') as f:
        return json.load(f)


j = load_json_file(f)
result = parse_policy(j)

print(result)
