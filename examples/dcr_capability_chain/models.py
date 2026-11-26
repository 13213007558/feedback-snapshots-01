"""In-memory SQLAlchemy models implementing the interfaces Authlib expects.

The Client mirrors the methods Authlib's grants call at runtime
(check_grant_type, get_allowed_scope, check_client_secret, ...). Crucially the
capability checks delegate to the live partner *policy* rather than trusting
only the snapshot stored at registration time, which is what makes tightening
an existing client take effect immediately.

The shared Policy is injected as a class attribute by the Database because
SQLAlchemy rebuilds instances without calling ``__init__``.
"""

import json
import secrets

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import reconstructor
from sqlalchemy.orm import sessionmaker

from .policy import Policy

Base = declarative_base()


def _scope_to_list(scope):
    return scope.split() if scope else []


class Client(Base):
    __tablename__ = "client"

    # Injected by Database before any client is loaded or queried.
    policy = None

    id = Column(Integer, primary_key=True)
    client_id = Column(String, unique=True, nullable=False)
    client_secret = Column(String, nullable=True)
    partner_id = Column(String, nullable=False)
    _metadata_json = Column("metadata_json", String, default="{}")

    @reconstructor
    def _reconstruct(self):
        # SQLAlchemy skips __init__ when loading a row; restore the snapshot.
        self.client_metadata = json.loads(self._metadata_json or "{}")

    def __init__(self, client_id, client_secret, partner_id, metadata):
        super().__init__()
        self.client_id = client_id
        self.client_secret = client_secret
        self.partner_id = partner_id
        # No instance policy: capability checks always read the class-level
        # policy injected by the current Database, so a runtime tightening is
        # observed by every client, including pre-existing ones.
        self.set_client_metadata(metadata)

    def set_client_metadata(self, metadata):
        self._metadata_json = json.dumps(metadata)
        self.client_metadata = dict(metadata)

    # --- identity / authentication (RFC 6749 client interface) ---
    @property
    def client_info(self):
        # RFC 7592 introspection merges client_info with client_metadata.
        info = {"client_id": self.client_id}
        if self.client_secret:
            info["client_secret"] = self.client_secret
            info["client_secret_expires_at"] = 0
        return info

    def get_client_id(self):
        return self.client_id

    def check_client_secret(self, secret):
        if not self.client_secret:
            return False
        return secrets.compare_digest(self.client_secret, secret or "")

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == "token":
            return (
                self.client_metadata.get(
                    "token_endpoint_auth_method", "client_secret_basic"
                )
                == method
            )
        return True

    # --- capability checks: live policy intersects the stored snapshot ---
    def _effective_grants(self):
        stored = set(self.client_metadata.get("grant_types", ["authorization_code"]))
        # The client can use only what is both on its record AND still approved.
        return stored & self.policy.grant(self.partner_id)

    def _effective_scopes(self):
        stored = set(_scope_to_list(self.client_metadata.get("scope", "")))
        return stored & self.policy.scopes(self.partner_id)

    def check_grant_type(self, grant_type):
        return grant_type in self._effective_grants()

    def check_response_type(self, response_type):
        allowed = self.client_metadata.get("response_types", ["code"])
        return response_type in allowed

    def get_allowed_scope(self, scope):
        effective = self._effective_scopes()
        return " ".join(s for s in _scope_to_list(scope) if s in effective)

    def get_default_redirect_uri(self):
        uris = self.client_metadata.get("redirect_uris", [])
        return uris[0] if uris else None

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.client_metadata.get("redirect_uris", [])


class RegistrationToken(Base):
    """RFC 7592 registration access token, scoped to one client."""

    __tablename__ = "registration_token"

    id = Column(Integer, primary_key=True)
    access_token = Column(String, unique=True, nullable=False)
    client_id = Column(String, nullable=False)
    revoked = Column(Integer, default=0)

    def check_client(self, client):
        return self.client_id == client.get_client_id()


class AccessToken(Base):
    __tablename__ = "access_token"

    id = Column(Integer, primary_key=True)
    access_token = Column(String, unique=True, nullable=False)
    client_id = Column(String, nullable=False)
    scope = Column(String, default="")
    revoked = Column(Integer, default=0)


class Database:
    def __init__(self, policy=None):
        self.engine = create_engine("sqlite://")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self.session = self.Session()
        self.policy = policy or Policy()
        Client.policy = self.policy

    def reset(self):
        self.session.rollback()
        Base.metadata.drop_all(self.engine)
        Base.metadata.create_all(self.engine)
