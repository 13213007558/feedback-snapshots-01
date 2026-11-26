Use an approved seed-wheel set
==============================

Internal build hosts can record which approval authorized a seed-wheel update.
The approval ledger lives in the shared AppData folder:

``<app-data>/seed-approval/ledger.json``

An approval document names the approval revision and approved mirror:

.. code-block:: json

    {
      "id": "wheel-approval-2026-11-26-01",
      "index_url": "https://wheels.example.invalid/simple",
      "wheels": {
        "setuptools": {
          "filename": "setuptools-92.0-py3-none-any.whl",
          "sha256": "..."
        }
      }
    }

Record a successful update from local wheel doubles or a synchronized mirror:

.. code-block:: python

    from virtualenv.app_data import AppDataDiskFolder
    from virtualenv.seed.wheels.approval import ApprovalLedger

    app_data = AppDataDiskFolder("/path/to/shared/virtualenv-app-data")
    ledger = ApprovalLedger(app_data)
    ready = ledger.record_update(
        "wheel-approval-2026-11-26-01",
        "3.12",
        ["/path/to/setuptools-92.0-py3-none-any.whl"],
    )

If an update fails, mark its attempt failed. The previous ready set stays active:

.. code-block:: python

    attempt = ledger.begin("wheel-approval-2026-11-26-02", "3.12")
    try:
        ...
    except Exception as exc:
        ledger.fail(attempt.id, exc)
        raise

An offline host points virtualenv at the same AppData and approval document (or
sets ``VIRTUALENV_SEED_APPROVAL``). virtualenv exports the document's
``index_url`` as ``PIP_INDEX_URL`` for any wheel lookup and reuses the last
ready set when the requested approval is not available offline. It marks the
receipt stale with the actual approval identifier:

.. code-block:: console

    python -m virtualenv .venv \
      --app-data /path/to/shared/virtualenv-app-data \
      --seed-approval /path/to/approval.json

The created environment contains ``seed-approval.json`` and
``pyvenv.cfg`` keys beginning with ``seed-approval-``. The JSON receipt records
the selected approval, set id, wheel digests, offline/stale state, and the
dist-info versions actually expanded into the environment.

The ledger module also has a JSON command line:

.. code-block:: console

    python -m virtualenv.seed.wheels.approval --app-data /path/to/app-data \
      show --for-py-version 3.12 --approval wheel-approval-2026-11-26-01
