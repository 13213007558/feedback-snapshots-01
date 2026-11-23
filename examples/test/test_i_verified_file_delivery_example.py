# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test the verified file delivery example runs end to end."""
import pytest

from ..src.verified_delivery.verified_file_delivery_example import main

pytestmark = [pytest.mark.examples, pytest.mark.local]


def test_verified_file_delivery_example():
    main()
