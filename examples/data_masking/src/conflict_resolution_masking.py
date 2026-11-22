from __future__ import annotations

import copy

from aws_lambda_powertools.utilities.data_masking import DataMasking
from aws_lambda_powertools.utilities.data_masking.exceptions import DataMaskingError
from aws_lambda_powertools.utilities.typing import LambdaContext

data_masker = DataMasking()

# Whole-field erase rules: everything under these containers is removed by default.
# Approved rules on sub-fields carve out the values that may leave the function masked.
masking_rules = {
    "customer": {},  # erase the whole customer object
    "notes": {},  # erase every element of the notes array
    "customer.contact.email": {"regex_pattern": r"(.)(.*)(@.*)", "mask_format": r"\1****\3"},
    "notes[*].author_email": {"custom_mask": "****@example.com"},
}


def lambda_handler(event: dict, context: LambdaContext) -> dict:
    record = event["body"]

    try:
        # Rules are resolved against the original record first, so registering them in a
        # different order returns the same public result.
        return data_masker.erase(copy.deepcopy(record), masking_rules=masking_rules)
    except DataMaskingError:
        # A rule that cannot be executed fails before any value is returned: the original
        # record stays intact and can be routed to a dead-letter queue instead of leaking.
        return {"status": "masking_failed", "record": record}
