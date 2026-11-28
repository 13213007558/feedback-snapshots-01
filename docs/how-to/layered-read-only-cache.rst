########################################
 Layer a read-only cache over a staging area
########################################

A build machine can hand every project the same pre-filled virtualenv application data cache, mounted
read-only. A project may still need a seed image that the shared cache does not ship. The layered application
data store keeps serving the shared content directly while materialising every cache miss inside a private
staging folder the project owns, so the shared tree is never written to and nothing is created outside the
staging path.

.. note::

    This is a programmatic entry point. It reuses the regular command line parsing and only swaps the
    application data store for a layered one before the environment is created.

*************************
 How the two layers behave
*************************

- The shared folder is opened through the read-only application data store. It is never written to and never
  receives a lock file; existing cache entries are read and reused as-is.
- The private staging folder is writable and holds every cache miss, generated wheel image, and lock.
- A path lookup reads the shared copy first and falls back to the private location on a miss.
- A failed image build removes its staging directory, mirroring the standard build recovery. A process killed
  before that cleanup can leave an orphaned staging directory, which is straightforward to audit afterwards.

*************************
 Create an environment
*************************

Pass the shared read-only folder and the private staging folder to :func:`~virtualenv.app_data.make_layered_app_data`,
or drive a full creation through ``cli_run_layered``. The remaining arguments are the usual virtualenv options;
use ``--extra-search-dir`` to point at a private index holding the missing wheels and ``--no-download`` to stay
offline.

.. code-block:: python

    from pathlib import Path

    from virtualenv.app_data.layered_run import cli_run_layered

    session, store = cli_run_layered(
        shared_folder="/opt/virtualenv/shared-cache",  # mounted read-only
        private_folder=str(Path("project/staging")),   # project-owned, writable
        args=[
            "project/.venv",
            "--setuptools", "bundle",
            "--extra-search-dir", "project/private-index",
            "--no-periodic-update",
            "--no-download",
        ],
    )

A seed already present in the shared cache (for example ``pip``) is read from it. A missing seed (for example
``setuptools``) is generated under ``project/staging`` and copied into the environment from there.

*************************
 Verify the guarantees
*************************

- Snapshot the shared tree before and after a run; the file set stays identical and the directory remains
  read-only.
- Inspect the private staging folder: the generated images and ``.lock`` files are the only new files, and they
  all stay below the staging root.
- After an injected failure, confirm no ``CopyPipInstall-*`` staging directory remains. To simulate a killed
  process, create such a directory by hand and check the audit finds and reaps it.

The repository ships a self-contained demonstration that runs two interleaved local sessions and the failure
recovery checks:

.. code-block:: console

    $ python tasks/layered_cache_demo.py
