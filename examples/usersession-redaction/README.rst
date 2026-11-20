User session client data redaction
===================================

Runnable demonstration of the configurable ``USERSESSIONS_CLIENT_IP_POLICY``
and ``USERSESSIONS_USER_AGENT_POLICY`` settings.

Run it from the repository root::

    python examples/usersession-redaction/demo_redaction.py

The script uses a temporary SQLite database and:

* logs in a desktop and a mobile client with distinct raw IP addresses and
  full user agent strings;
* lists the sessions through the browser management page and the headless
  API, asserting that only the masked network address and the device category
  are exposed;
* ends the mobile session through the headless API using its stable session
  id, verifying that exactly that session is removed;
* verifies the browser "Sign Out Other Sessions" flow still works;
* scans every stored database cell to make sure no raw IP address or full
  user agent string is persisted.
