Session-file resume: what it does and does not restore
======================================================

``Client.session_state_path`` makes ``connect()`` try ``ActivateSession`` on a
token read from disk before falling back to ``CreateSession``. The file holds
``authentication_token``, ``server_nonce`` and ``saved_at``, written with mode
``0o600`` through a temporary file and ``os.replace``.

What the file actually restores
===============================

The file is a bearer credential for one session on one server process. It does
not contain an identity, a password, a client certificate, an application URI,
a policy selection, or any subscription objects.

- **Server instance.** ``InternalSession`` keeps external sessions in
  ``InternalServer._external_sessions``, keyed by a server-local
  ``AuthenticationToken``. A second server has no entry for that token, so a
  copied file causes a fresh session there, not a continuation.
- **Server certificate and policy.** The stored nonce and token belong to the
  endpoint that issued them. The client still selects the endpoint and policy
  from its own configuration; resume does not pin either. Resuming over
  ``SecurityPolicy#None`` after an earlier secure session is accepted by the
  current client and demoed in ``examples/client-session-resume.py``.
- **Username.** ``ActivateSession`` always carries a user identity token from
  the new client's configuration, not from the file. A valid second identity
  can therefore present the first user's file, and the server then reassigns
  the existing ``InternalSession.user`` to the second identity.
- **SessionId.** Only the authentication token is stored. The server derives
  ``SessionId`` internally; the client never presents it on resume.
- **ActivateSession proof.** ``ClientSignature`` is an asymmetric signature over
  ``serverCertificate + serverNonce`` when a policy is in use, and empty under
  ``SecurityPolicy#None``. The nonce rotates on every successful activation, so
  any file copy taken before a later activation has a stale nonce. Under a
  policy that verifies ``ClientSignature`` this replay is rejected; under
  ``SecurityPolicy#None`` the check is a no-op and the stale copy is accepted.
- **Timeout state.** The server keeps an activated external session after
  transport loss only while it owns at least one subscription, and closes it
  after ``session_timeout`` of inactivity. The client does not use the file's
  ``saved_at`` to decide whether to try: that timestamp is only refreshed on
  connect/resume, not by keepalive traffic, so an old timestamp can coexist with
  a live session. The server's answer to ``ActivateSession`` is authoritative.
  A credential or transport failure leaves the file in place, because the
  session may still be resumable; only ``BadSessionIdInvalid`` /
  ``BadSessionClosed`` deletes it. ``disconnect()`` deletes the file only for a
  client that actually wrote it, so a client whose resume attempt failed does
  not erase another process's resume state.

Same trusted server, same identity
----------------------------------

Given an unexpired server-side session, a current nonce, and matching
credentials, resume keeps the authentication token and the server-side
subscription survives. The new connection must still complete
``ActivateSession`` with its own verified identity. The client does not
reconstruct ``Subscription`` objects from the file: after a restart it has no
local subscription list, callback map, or publish task. The server subscription
still exists and its retained notifications can be pulled with ``Publish`` /
``Republish``, but the returned high-level client object has no local
subscription state until it issues ``CreateSubscription`` or
``TransferSubscriptions`` itself.

Certificate rotation
--------------------

A rotated client certificate is a new application instance identity only at the
channel level. Resume still re-sends the configured username/password or
certificate token. In the demo, a session created with client certificate 1 is
resumed with client certificate 2 when the username and password match; the
existing server session is reactivated and retains its subscription. With an
invalid password the server rejects the activation and leaves the original
session intact. What the file can never do is supply the credential that the
new client must present.

Wrong user's file
-----------------

A copied file presented with another valid user's credentials activates the
same server-side session and changes its owner. Under ``SecurityPolicy#None``,
or whenever the copied nonce is still current, the server-side subscription of
the first user follows the new identity. A file taken from a different user is
therefore not a harmless "resume"; it is a session-handover primitive. File ACLs
are the only control the current design places on who can use it, so the file
must be treated like a private key: same UID, ``0o600``, no shared backups, no
world-readable container layers, and no copying to a standby host.

Closed or expired sessions
--------------------------

A session closed by ``CloseSession``, deleted server-side, or expired after
``session_timeout`` is gone from ``_external_sessions``. Keeping the file does
not revive it: ``ActivateSession`` fails and the client falls back to
``CreateSession``. That fallback uses the client's configured username/password,
certificate, or anonymous mode, never a credential read from the file. If no
credential is configured, the fallback is anonymous (or rejected by a strict
``UserManager``); it must be treated as a new, separately authorized session.

Reconnect versus resume
-----------------------

An in-process transport drop is handled by the auto-reconnect supervisor, which
keeps the live token and nonce in memory and re-activates the session. It now
rewrites ``session_state_path`` after reactivation, so a later process crash
does not present a stale nonce. The file path is only for a new process. Do not
use both mechanisms against the same session at the same time: two clients can
activate one token, and the first ``CloseSession`` then invalidates the other
connection.

Standby-node constraints
------------------------

Copying the file to a standby node does not provide high availability by
itself. The standby server has no entry for the token and cannot continue the
session; at best it creates a new session for the copied credentials. A usable
design needs all of the following:

1. Session state stays on the node that owns the server session, or the
   session is recreated rather than resumed on failover.
2. Credentials are resolved from the client's own protected configuration on
   the node that reconnects; the file is never the credential source.
3. The client re-establishes subscriptions explicitly (``CreateSubscription``
   or ``TransferSubscriptions`` plus ``Republish``) because the file does not
   carry them.
4. The file is treated as a bearer secret: encrypted at rest or an equivalent
   OS-protected secret store, owner-only permissions, excluded from backups and
   image layers, rotated on any suspected copy, and deleted on graceful close.
5. Activation is restricted to the intended identity. The current server
   accepts a valid token plus any valid identity, so a known or leaked token is
   enough to take over a session. Tokens are now random GUIDs rather than
   sequential integers, which removes trivial guessing and cross-server
   collisions, but does not make disclosure harmless: network access and file
   access remain the controls.
6. A copied file replayed after the nonce rotates is rejected only when a
   security policy verifies ``ClientSignature``; do not rely on file secrecy
   under ``SecurityPolicy#None``.

What the server revalidates on resume
-------------------------------------

On a new SecureChannel, ``ActivateSession`` verifies the ``ClientSignature``
against the current server certificate and the session's current nonce, then
validates the identity token through ``UserManager``. It does not compare the
new identity to the session's previous owner, does not bind the session to a
client certificate, and does not check ``ApplicationUri``. It also does not
verify that the caller holds any local file at all; the token alone selects the
session. The client-side file adds no proof to that exchange.

Server binding bug fixed alongside this review
----------------------------------------------

Two server-side defects were fixed alongside this review. ``UaProcessor``
assigned ``self.session`` from the presented token before verifying
``ClientSignature`` and the identity token, so a rejected ``ActivateSession``
still left the processor bound to the victim session and a subsequent ``Read``
succeeded; the binding now happens only after activation succeeds. The
authentication token, previously a per-process sequential integer, is now a
random GUID, removing guessing and cross-server collision. Both are covered by
``tests/test_session_resume_resources.py``; neither substitutes for the
identity check and file protection described above.

Local demo
----------

``examples/client-session-resume.py`` runs the real OPC UA binary exchange over
in-process socketpairs and covers: same-identity resume, cross-identity
takeover, deleted/expired sessions, bare-file rejection and permissive-manager
acceptance, certificate rotation, stale-nonce replay, wrong password, policy
downgrade, live-session resume with an old ``saved_at``, disclosed-token
activation, and a file copied to an independent server. It prints keyed token
references and never prints the token or nonce.
