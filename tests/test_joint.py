import threading
import time
import unittest
from flask import Flask, request
from flask_httpauth import HTTPTokenAuth, MultiAuth, JointAuth


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


class JointAuthTestCase(unittest.TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'my secret'

        service_auth = HTTPTokenAuth(header='X-Service-Token')
        operator_auth = HTTPTokenAuth(header='X-Operator-Token')
        joint_auth = JointAuth(service_auth, operator_auth)
        multi_auth = MultiAuth(service_auth, operator_auth)
        store = ApprovalStore()
        self.store = store
        self.entered = []

        @service_auth.verify_token
        def verify_service_token(token):
            if token == 'svc-token-1':
                return 'svc-1'

        @service_auth.get_user_roles
        def get_service_roles(service):
            if service == 'svc-1':
                return ['service', 'approver']

        @operator_auth.verify_token
        def verify_operator_token(token):
            if token == 'op-token-1':
                return 'alice'
            if token == 'op-token-2':
                return 'bob'

        @operator_auth.get_user_roles
        def get_operator_roles(operator):
            if operator == 'alice':
                return ['operator', 'approver']
            if operator == 'bob':
                return ['operator']

        @joint_auth.authorize
        def authorize_approval(service, operator):
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
        def joint_route(ticket, action):
            self.entered.append((ticket, action))
            service = joint_auth.current_user(service_auth)
            operator = joint_auth.current_user(operator_auth)
            return f'{service}:{operator}:{ticket}:{action}'

        @app.route('/tickets-with-role/<ticket>/<action>')
        @joint_auth.login_required(role='approver')
        def joint_role_route(ticket, action):
            self.entered.append((ticket, action))
            return 'role access granted'

        @app.route('/service-only')
        @service_auth.login_required
        def service_only_route():
            return 'service only:' + str(service_auth.current_user())

        @app.route('/multi')
        @multi_auth.login_required
        def multi_route():
            return 'multi:' + str(multi_auth.current_user())

        now = time.time()
        store.issue('approval-1', 'svc-1', 'alice', 'T-1', 'approve',
                    now + 3600)
        store.issue('approval-expired', 'svc-1', 'alice', 'T-1', 'approve',
                    now - 1)
        store.issue('approval-other-ticket', 'svc-1', 'alice', 'T-2',
                    'approve', now + 3600)
        store.issue('approval-bob', 'svc-1', 'bob', 'T-1', 'approve',
                    now + 3600)

        self.app = app
        self.client = app.test_client()

    def test_joint_requires_two_auths(self):
        with self.assertRaises(ValueError):
            JointAuth(HTTPTokenAuth())

    def test_joint_success(self):
        response = self.client.get('/tickets/T-1/approve', headers=creds())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'),
                         'svc-1:alice:T-1:approve')
        self.assertNotIn('approval-1', response.data.decode('utf-8'))
        self.assertTrue(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [('T-1', 'approve')])

    def test_joint_missing_operator(self):
        response = self.client.get('/tickets/T-1/approve',
                                   headers=creds(operator=None))
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertFalse(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [])

    def test_joint_missing_service(self):
        response = self.client.get('/tickets/T-1/approve',
                                   headers=creds(service=None))
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertFalse(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [])

    def test_joint_invalid_operator_not_consumed(self):
        response = self.client.get('/tickets/T-1/approve',
                                   headers=creds(operator='bad-token'))
        self.assertEqual(response.status_code, 401)
        self.assertFalse(self.store.is_consumed('approval-1'))
        # the credential is still redeemable after the failed attempt
        response = self.client.get('/tickets/T-1/approve', headers=creds())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(self.store.is_consumed('approval-1'))

    def test_joint_scope_mismatch_ticket(self):
        response = self.client.get(
            '/tickets/T-1/approve', headers=creds(
                approval='approval-other-ticket'))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-other-ticket'))
        self.assertEqual(self.entered, [])

    def test_joint_scope_mismatch_action(self):
        response = self.client.get('/tickets/T-1/close', headers=creds())
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-1'))
        self.assertEqual(self.entered, [])

    def test_joint_expired(self):
        response = self.client.get(
            '/tickets/T-1/approve', headers=creds(approval='approval-expired'))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-expired'))
        self.assertEqual(self.entered, [])

    def test_joint_role_success(self):
        response = self.client.get('/tickets-with-role/T-1/approve',
                                   headers=creds())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'role access granted')

    def test_joint_role_failure_not_consumed(self):
        response = self.client.get(
            '/tickets-with-role/T-1/approve',
            headers=creds(operator='op-token-2', approval='approval-bob'))
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.store.is_consumed('approval-bob'))
        self.assertEqual(self.entered, [])

    def test_joint_concurrent_single_consume(self):
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

    def test_joint_credential_not_in_error_responses(self):
        response = self.client.get('/tickets/T-1/approve',
                                   headers=creds(operator=None))
        self.assertNotIn('approval-1', response.data.decode('utf-8'))
        response = self.client.get('/tickets/T-1/close', headers=creds())
        self.assertNotIn('approval-1', response.data.decode('utf-8'))

    def test_single_auth_route_still_works(self):
        response = self.client.get('/service-only',
                                   headers={'X-Service-Token': 'svc-token-1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'service only:svc-1')
        response = self.client.get('/service-only')
        self.assertEqual(response.status_code, 401)

    def test_multi_auth_route_still_works(self):
        response = self.client.get('/multi',
                                   headers={'X-Service-Token': 'svc-token-1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'multi:svc-1')
        response = self.client.get('/multi',
                                   headers={'X-Operator-Token': 'op-token-1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data.decode('utf-8'), 'multi:alice')
        response = self.client.get('/multi')
        self.assertEqual(response.status_code, 401)
