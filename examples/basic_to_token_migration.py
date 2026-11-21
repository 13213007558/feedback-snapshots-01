#!/usr/bin/env python
"""Basic-to-Token migration example

This example shows how to run HTTP Basic and Bearer token authentication
side by side while clients are migrated from passwords to tokens, without
ever exposing plaintext passwords to the new token endpoints.

Fixture accounts:
  - legacy client:  Authorization: Basic am9objpoZWxsbw==  (john / hello)
  - modern client:  Authorization: Bearer token-for-jane

Run the server and try:
  curl -u john:hello http://localhost:5000/
  curl -H "Authorization: Bearer token-for-jane" http://localhost:5000/
  curl -u john:hello -X POST http://localhost:5000/tokens
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import Flask, g, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth

app = Flask(__name__)

basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth(scheme='Bearer')
multi_auth = MultiAuth(basic_auth, token_auth)


# --- "database" fixture -------------------------------------------------
# accounts: the pre-existing table. It only ever stores a password hash.
# tokens: the new table. It stores a hash of each token, never the token.
db = {
    'accounts': {
        'john': {
            'id': 1,
            'password_hash': generate_password_hash('hello'),
        },
        'jane': {
            'id': 2,
            'password_hash': generate_password_hash('bye'),
        },
    },
    'tokens': {
        # token_hash -> record
        hashlib.sha256(b'token-for-jane').hexdigest(): {
            'user_id': 2,
            'expires_at': datetime.now(timezone.utc) + timedelta(days=30),
            'revoked': False,
        },
    },
}


def find_user_by_id(user_id):
    for username, account in db['accounts'].items():
        if account['id'] == user_id:
            return username


# --- legacy path: reads accounts.password_hash ---------------------------
@basic_auth.verify_password
def verify_password(username, password):
    account = db['accounts'].get(username)
    if account and check_password_hash(account['password_hash'], password):
        g.auth_method = 'basic'
        return username


# --- new path: reads tokens.token_hash / expires_at / revoked ------------
@token_auth.verify_token
def verify_token(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    record = db['tokens'].get(token_hash)
    if record is None or record['revoked']:
        return None
    if record['expires_at'] < datetime.now(timezone.utc):
        return None
    g.auth_method = 'token'
    return find_user_by_id(record['user_id'])


@app.route('/')
@multi_auth.login_required
def index():
    return jsonify(user=multi_auth.current_user(),
                   auth_method=g.get('auth_method'))


# Token issuance: during migration the only endpoint that still requires
# Basic. It never sees or stores a plaintext password afterwards.
@app.route('/tokens', methods=['POST'])
@basic_auth.login_required
def issue_token():
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db['tokens'][token_hash] = {
        'user_id': db['accounts'][basic_auth.current_user()]['id'],
        'expires_at': datetime.now(timezone.utc) + timedelta(days=30),
        'revoked': False,
    }
    return jsonify(token=token, token_type='Bearer')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
