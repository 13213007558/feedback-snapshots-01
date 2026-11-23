# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import json
import os

import botocore.session
from botocore.loaders import Loader

SERVICE = 'sqs'
API_VERSION = '2012-11-05'
OPERATION = 'SendMessage'
TEAM_DOCUMENTATION = '<p>team supplemental documentation</p>'


def _write_supplemental_model(root, model):
    dirname = os.path.join(root, SERVICE, API_VERSION)
    os.makedirs(dirname)
    full_path = os.path.join(dirname, 'service-2.json')
    with open(full_path, 'w') as f:
        json.dump(model, f)
    return full_path


def _create_client(loader):
    session = botocore.session.Session()
    session.register_component('data_loader', loader)
    return session.create_client(
        SERVICE,
        region_name='us-east-1',
        aws_access_key_id='foo',
        aws_secret_access_key='bar',
    )


def _client_auth_decision(client):
    operation = client.meta.service_model.operation_model(OPERATION)
    return {
        'documentation': operation.documentation,
        'auth_type': operation.auth_type,
    }


def test_supplemental_docs_apply_but_auth_change_is_blocked(tmp_path):
    docs_path = tmp_path / 'docs'
    auth_path = tmp_path / 'auth'

    # The first supplemental model only overrides the operation's
    # documentation.
    _write_supplemental_model(
        str(docs_path),
        {'operations': {OPERATION: {'documentation': TEAM_DOCUMENTATION}}},
    )
    loader = Loader(
        extra_search_paths=[str(docs_path)],
        allow_supplemental_models=True,
    )
    decision_before_reload = _client_auth_decision(_create_client(loader))
    assert decision_before_reload['documentation'] == TEAM_DOCUMENTATION
    assert decision_before_reload['auth_type'] is None
    assert loader.supplemental_audit_log == []

    # A second supplemental model now attempts to change the same
    # operation's auth declaration.  Reloading (a fresh loader with both
    # supplemental paths) must keep the released auth requirements while
    # the documentation layer still applies.
    _write_supplemental_model(
        str(auth_path),
        {'operations': {OPERATION: {'authtype': 'none'}}},
    )
    reloaded_loader = Loader(
        extra_search_paths=[str(docs_path), str(auth_path)],
        allow_supplemental_models=True,
    )
    decision_after_reload = _client_auth_decision(
        _create_client(reloaded_loader)
    )
    assert decision_after_reload['documentation'] == TEAM_DOCUMENTATION
    assert decision_after_reload['auth_type'] is None

    # The blocked change identifies both the operation and its source.
    audit_log = reloaded_loader.supplemental_audit_log
    assert len(audit_log) == 1
    record = audit_log[0]
    assert record['service_name'] == SERVICE
    assert record['api_version'] == API_VERSION
    assert record['operation_name'] == OPERATION
    assert record['key'] == 'authtype'
    assert record['blocked_value'] == 'none'
    assert record['retained_value'] is None
    assert record['source_path'] == os.path.join(
        str(auth_path), SERVICE, API_VERSION, 'service-2'
    )
    assert os.path.isfile(record['source_path'] + '.json')
