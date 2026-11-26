Added
~~~~~

- ``RefreshTokenGrant.revalidate_refresh_token()`` re-reads a refresh
  credential immediately before token issuance and persistence, so a
  revocation after request validation can reject the pending refresh.
- ``RefreshTokenGrant.rotate_refresh_token()`` groups new-token persistence
  and old-credential retirement. Storage backends can override it with an
  atomic grant-generation compare-and-set.

Changed
~~~~~~~

- The SQLAlchemy revocation endpoint preserves the first revocation
  timestamp for repeated idempotent revocation requests.
