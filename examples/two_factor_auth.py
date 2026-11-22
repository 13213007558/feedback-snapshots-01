#!/usr/bin/env python
"""Two-factor authentication example.

The ``MultiAuth`` class combines authentication objects with an "or" rule,
granting access when any one of the methods validates. A restricted endpoint
that must confirm *both* a service identity and a one-time proof from the
operator instead stacks the ``login_required`` decorators of two independent
authentication objects. Both proofs must validate before the view runs.

The two factors are intentionally carried on different headers:

* HTTP Basic credentials in ``Authorization`` identify the calling service.
* A one-time token in the ``X-OTP`` header identifies the operator.

Other endpoints in this application continue to accept a single factor.

Run with::

    python examples/two_factor_auth.py
"""
from flask import Flask, g, jsonify
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

app = Flask(__name__)

service_auth = HTTPBasicAuth()
otp_auth = HTTPTokenAuth(header='X-OTP')

# Fake service directory: service id -> shared secret.
services = {
    'billing-service': 'service-secret',
}

# Fake one-time password store: operator -> currently valid OTP. In a real
# application each code would be invalidated after a single successful use.
one_time_passwords = {
    'alice': '424242',
    'bob': '909090',
}


@service_auth.verify_password
def verify_service(username, password):
    # First fake validator: the service credential proof.
    if username in services and services[username] == password:
        g.two_factor_service = {'service_id': username}
        return username
    return None


@otp_auth.verify_token
def verify_otp(token):
    # Second fake validator: the operator's one-time proof.
    for operator, otp in one_time_passwords.items():
        if otp == token:
            g.two_factor_operator = {'operator': operator, 'otp': token}
            return operator
    return None


@service_auth.error_handler
def service_auth_error(status):
    return jsonify(error='valid service credentials required'), status


@otp_auth.error_handler
def otp_auth_error(status):
    return jsonify(error='a valid one-time token is required'), status


@app.route('/public')
def public():
    return jsonify(message='no authentication required')


@app.route('/service-only')
@service_auth.login_required
def service_only():
    # Single-factor endpoint kept open to service credentials alone.
    return jsonify(service=g.two_factor_service)


@app.route('/operator-only')
@otp_auth.login_required
def operator_only():
    # Single-factor endpoint kept open to the one-time token alone.
    return jsonify(operator=g.two_factor_operator)


@app.route('/restricted')
@service_auth.login_required
@otp_auth.login_required
def restricted():
    # Two-factor endpoint: both validators must pass. Each identity is read
    # from its own key because the auth objects share the framework's default
    # current-user slot.
    return jsonify(
        service=g.two_factor_service,
        operator=g.two_factor_operator,
    )


if __name__ == '__main__':
    app.run()
