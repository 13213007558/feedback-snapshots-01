Approve dependency artifacts
=============================

Use ``artifact_approvals`` to enforce that both layered requirements and ``pylock`` installs use artifacts approved
for this build. tox resolves the requirement or lock entry to its concrete local path/URL and SHA-256 identity before
invoking pip; the same evidence object is passed to the installer boundary and written under
``.tox/<env>/approvals/``.

Create an ``approvals.json`` (or ``approvals.toml``) policy:

.. code-block:: json

    {
      "approvals": [
        {
          "id": "ticket-123",
          "name": "dist-name",
          "version": "1.0",
          "path": "wheelhouse/dist_name-1.0-py3-none-any.whl",
          "sha256": "artifact-digest",
          "status": "approved"
        }
      ]
    }

Then point tox at it when the file uses another name:

.. code-block:: toml

    [env_run_base]
    artifact_approvals = "approvals.json"

Approval is intentionally bound to the concrete source and digest, not only name/version. Two local wheels with the
same name and version therefore need separate approvals. Markers, constraints and the target interpreter are applied
while resolving which requirement artifacts are active.

Every run re-reads the current policy before trusting the install cache. Revoking an entry fails that environment even
when its version is already installed. Unaffected environments keep their normal cache hit and can still run commands.

For an existing environment, check current approvals without installing:

.. code-block:: console

    tox approvals -e py
    tox approvals --json -e py
