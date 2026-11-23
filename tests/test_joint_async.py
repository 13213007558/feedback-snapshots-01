import sys
import threading
import time
import unittest
from flask import Flask, request
from flask_httpauth import HTTPTokenAuth, JointAuth
import pytest


class ApprovalStore:
    """Caller-provided storage for approval credentials. Consumption is
    atomic, so a credential can only be redeemed once."""
    def __init__(self):
        self._lock = threading.Lock()
        self._records = {}

    def issue(self, token, service, operator, ticket, action, expires_at):
        with self._lock:
            self._records[token] = {
                'service': service,
                'operator': operator,
                'ticket': ticket,
                'action': action,
                'expires_at': expires_at,
                'consumed': False,
            }

    def get(self, token):
        with self._lock:
            record = self._records.get(token)
            return dict(record) if record is not None else None

    def consume(self, token):
        with self._lock:
            record = self._records.get(token)
            if record is None or record['consumed']:
                return False
            record['consumed'] = True
            return True

    def is_consumed(self, token):
        with self._lock:
            return self._records[token]['consumed']


def creds(service='svc-token-1', operator='op-token-1', approval='approval-1'):
    headers = {}
    if service is not None:
        headers['X-Service-Token'] = service
    if operator is not None:
        headers['X-Operator-Token'] = operator
    if approval is not None:
        headers['X-Approval-Token'] = approval
    return headers


@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class JointAuthAsyncTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        service_auth = HTTPTokenAuth(header='X-Service-Token')
        operator_auth = HTTPTokenAuth(header='X-Operator-Token')
        joint_auth = JointAuth(service_auth, operator_auth)
        store = ApprovalStore()
        self.store = store
        self.entered = []

        @service_auth.verify_token
        async def verify_service_token(token):
            if token == 'svc-token-1':
                return 'svc-1'

        @service_auth.get_user_roles
        async def get_service_roles(service):
            if service == 'svc-1':
                return ['service', 'approver']

        @operator_auth.verify_token
        async def verify_operator_token(token):
            if token == 'op-token-1':
                return 'alice'
            if token == 'op-token-2':
                return 'bob'

        @operator_auth.get_user_roles
        async def get_operator_roles(operator):
            if operator == 'alice':
                return ['operator', 'approver']
            if operator == 'bob':
                return ['operator']

        @joint_auth.authorize
        async def authorize_approval(service, operator):
            token = request.headers.get('X-Approval-Token', '')
            record = store.get(token)
            if record is None:
                return False
            if record['service'] != service or \
                    record['operator'] != operator:
                return False
            if record['ticket'] != request.view_args['ticket'] or \
                    record['action'] != request.view_args['action']:
                return False
            if record['expires_at'] <= time.time():
                return False
            return store.consume(token)

        @app.route('/tickets/<ticket>/<action>')
        @joint_auth.login_required
        async def joint_route(ticket, action):
            self.entered.append((ticket, action))
            service = joint_auth.current_user(service_auth)
            operator = joint_auth.current_user(operator_auth)
            return f'{service}:{operator}:{ticket}:{action}'

        @app.route('/tickets-with-role/<ticket>/<action>')
        @joint_auth.login_required(role='approver')
        async def joint_role_route(ticket, action):
            self.entered.append((ticket, action))
            return 'role access granted'

        now = time.time()
        store.issue('approval-1', 'svc-1', 'alice', 'T-1', 'approve',
                    now + 3600)

        self.app = app
        self.client = app.test_client()

    def test_joint_async_success(self):
        response = self.client.get('/tickets/T-1/approve', headers=creds())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'),
                         'svc-1:alice:T-1:approve')
        self.assertNotIn('approval-1', response.data.decode('utf-8'))
        self.assertTrue(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [('T-1', 'approve')])

    def test_joint_async_missing_operator(self):
        response = self.client.get('/tickets/T-1/approve',
                                   headers=creds(operator=None))
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertFalse(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [])

    def test_joint_async_scope_mismatch(self):
        response = self.client.get('/tickets/T-1/close', headers=creds())
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [])

    def test_joint_async_expired(self):
        self.store.issue('approval-expired', 'svc-1', 'alice', 'T-1',
                         'approve', time.time() - 1)
        response = self.client.get(
            '/tickets/T-1/approve', headers=creds(approval='approval-expired'))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-expired'))
        self.assertEqual(self.entered, [])

    def test_joint_async_role_failure_not_consumed(self):
        self.store.issue('approval-bob', 'svc-1', 'bob', 'T-1', 'approve',
                         time.time() + 3600)
        response = self.client.get(
            '/tickets-with-role/T-1/approve',
            headers=creds(operator='op-token-2', approval='approval-bob'))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-bob'))
        self.assertEqual(self.entered, [])

    def test_joint_async_concurrent_single_consume(self):
        self.store.issue('approval-race', 'svc-1', 'alice', 'T-9', 'approve',
                         time.time() + 3600)
        barrier = threading.Barrier(2)
        statuses = []

        def worker():
            client = self.app.test_client()
            barrier.wait()
            response = client.get(
                '/tickets/T-9/approve',
                headers=creds(approval='approval-race'))
            statuses.append(response.status_code)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(sorted(statuses), [200, 403])
        self.assertEqual(self.entered, [('T-9', 'approve')])
        self.assertTrue(self.store.is_consumed('approval-race'))
