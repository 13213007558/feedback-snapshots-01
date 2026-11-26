"""Flask assembly exposing the four layers over HTTP (in-process test client).

Routes:
  GET  /.well-known/oauth-authorization-server  discovery (RFC 8414)
  POST /register                                 dynamic registration (RFC 7591)
  GET/PUT/DELETE /register/<client_id>           management (RFC 7592)
  POST /oauth/token                              token grant (RFC 6749)

No network port is opened: callers use Flask's test_client, so the demo runs
inside sandboxes that forbid binding a local port.
"""

from flask import Flask
from flask import jsonify

from authlib.integrations.flask_oauth2 import AuthorizationServer
from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc8414 import AuthorizationServerMetadata

from .endpoints import ConfigurationEndpoint
from .endpoints import RegistrationEndpoint
from .grants import ScopedClientCredentialsGrant
from .models import Client
from .models import Database
from .policy import SERVER_GRANTS
from .policy import SERVER_SCOPES

ISSUER = "https://as.example.test"


def build_server_metadata(policy):
    # Discovery only advertises the server ceiling. Per-partner entitlements
    # are NOT published here; they are enforced per request.
    metadata = AuthorizationServerMetadata(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/oauth/authorize",
            "token_endpoint": f"{ISSUER}/oauth/token",
            "registration_endpoint": f"{ISSUER}/register",
            "grant_types_supported": SERVER_GRANTS,
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "scopes_supported": SERVER_SCOPES,
        }
    )
    metadata.validate()
    return metadata


def create_app(policy=None, legacy_client=None):
    app = Flask(__name__)
    app.testing = True
    db = Database(policy=policy)

    # Optionally seed a client registered before the policy was tightened.
    if legacy_client is not None:
        db.session.add(legacy_client)
        db.session.commit()

    metadata = build_server_metadata(db.policy)

    def query_client(client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def save_token(token, request):
        # The grant persists the token itself; this hook satisfies Authlib.
        return None

    server = AuthorizationServer(app, query_client, save_token)
    server.demo_db = db
    server.scopes_supported = SERVER_SCOPES
    server.register_grant(ScopedClientCredentialsGrant)
    server.register_endpoint(RegistrationEndpoint(server, db, metadata))
    server.register_endpoint(ConfigurationEndpoint(server, db, metadata))

    @app.get("/.well-known/oauth-authorization-server")
    def discovery():
        return jsonify(dict(metadata))

    @app.post("/register")
    def register():
        return server.create_endpoint_response("client_registration")

    @app.route("/register/<client_id>", methods=["GET", "PUT", "DELETE"])
    def configure(client_id):
        return server.create_endpoint_response("client_configuration")

    @app.post("/oauth/token")
    def token():
        return server.create_token_response()

    @app.errorhandler(OAuth2Error)
    def handle_oauth2_error(error):
        # Single place that turns every layer's decision into RFC-shaped JSON:
        # status, error code, human description, and WWW-Authenticate on 401.
        payload = {"error": error.error}
        if error.description:
            payload["error_description"] = error.description
        response = jsonify(payload)
        response.status_code = error.status_code
        if error.status_code == 401:
            response.headers["WWW-Authenticate"] = "Bearer"
        return response

    return app, db, server
