import sys
import unittest
import base64
from flask import Blueprint, Flask
from flask_httpauth import HTTPBasicAuth
import pytest


def build_app(async_views=False):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'my secret'

    auth = HTTPBasicAuth()
    content_bp = Blueprint('content', __name__)

    @content_bp.route('/content')
    @auth.login_required
    def content():
        return 'content:' + str(auth.current_user())

    if async_views:
        @auth.verify_password
        async def verify_password(username, password):
            if password == 'ok':
                return username

        @app.route('/preview')
        @auth.login_required
        async def preview():
            with auth.internal_auth_context('preview-service'):
                inner = content()
                during = auth.current_user()
            after = auth.current_user()
            return '{}/during:{}/after:{}'.format(inner, during, after)

        @app.route('/preview-error')
        @auth.login_required
        async def preview_error():
            try:
                with auth.internal_auth_context('preview-service'):
                    raise RuntimeError('boom')
            except RuntimeError:
                pass
            return 'after:' + str(auth.current_user())
    else:
        @auth.verify_password
        def verify_password(username, password):
            if password == 'ok':
                return username

        @app.route('/preview')
        @auth.login_required
        def preview():
            with auth.internal_auth_context('preview-service'):
                inner = content()
                during = auth.current_user()
            after = auth.current_user()
            return '{}/during:{}/after:{}'.format(inner, during, after)

        @app.route('/preview-error')
        @auth.login_required
        def preview_error():
            try:
                with auth.internal_auth_context('preview-service'):
                    raise RuntimeError('boom')
            except RuntimeError:
                pass
            return 'after:' + str(auth.current_user())

    app.register_blueprint(content_bp)
    return app, auth


class InternalAuthContextTestCase(unittest.TestCase):
    def setUp(self):
        self.app, self.auth = build_app()
        self.client = self.app.test_client()

    def get(self, url, username=None, password=None):
        headers = {}
        if username is not None:
            creds = base64.b64encode(
                '{}:{}'.format(username, password).encode('utf-8')).decode(
                    'utf-8')
            headers['Authorization'] = 'Basic ' + creds
        return self.client.get(url, headers=headers)

    def test_direct_access_unauthenticated(self):
        response = self.get('/content')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_direct_access_authenticated(self):
        response = self.get('/content', 'john', 'ok')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'content:john')

    def test_internal_preview(self):
        response = self.get('/preview', 'john', 'ok')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            b'content:preview-service/during:preview-service/after:john')

    def test_internal_preview_unauthenticated(self):
        response = self.get('/preview')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)

    def test_internal_preview_error_exit(self):
        response = self.get('/preview-error', 'john', 'ok')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'after:john')

    def test_internal_context_does_not_leak(self):
        response = self.get('/preview', 'john', 'ok')
        self.assertEqual(response.status_code, 200)
        # subsequent requests must authenticate normally
        response = self.get('/content')
        self.assertEqual(response.status_code, 401)
        response = self.get('/content', 'susan', 'ok')
        self.assertEqual(response.data, b'content:susan')


@pytest.mark.skipif(sys.version_info < (3, 7), reason='requires python3.7')
class InternalAuthContextAsyncTestCase(InternalAuthContextTestCase):
    def setUp(self):
        self.app, self.auth = build_app(async_views=True)
        self.client = self.app.test_client()
