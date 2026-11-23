ADC provenance diagnostics
==========================

A project ID alone does not identify which credential was used. Two completely
different environments can return the same project ID:

* a developer workstation using an ``authorized_user`` file under the Cloud SDK
  configuration directory, where the project comes from
  ``gcloud config get project``;
* a managed workload using Compute Engine credentials, where the project comes
  from the metadata server.

When a machine has been migrated, either case can be the one actually selected.
This page describes how to tell them apart without reading credentials.

.. note::

   The procedure here is offline by design. Do not attach real credential files,
   refresh tokens, private keys, or access tokens to a support ticket. Use the
   diagnostic script and the synthetic scenarios below. If you need real values,
   collect only the non-secret fields listed at the end of this page.

Discovery order
---------------

:func:`google.auth.default` evaluates these stages in order and stops at the
first stage that returns credentials:

1. ``GOOGLE_APPLICATION_CREDENTIALS``, if set to a non-empty path.
2. The Cloud SDK default file
   (``$CLOUDSDK_CONFIG/application_default_credentials.json`` or
   ``~/.config/gcloud/application_default_credentials.json``), then
   ``gcloud config get project`` if the file carries no project ID.
3. App Engine standard (first generation) App Identity credentials.
4. Compute Engine / Cloud Run / App Engine flexible metadata credentials.
5. :class:`~google.auth.exceptions.DefaultCredentialsError` if nothing is found.

Two details matter for migration investigations:

* If ``GOOGLE_APPLICATION_CREDENTIALS`` is set to exactly the Cloud SDK default
  path, stage 1 delegates to stage 2. The Cloud SDK file is then optional: a
  missing file at that path is a probe that moves on to the next stage, not an
  error.
* A path that is *not* the Cloud SDK default path is a strict instruction. If
  the file is missing, unreadable, or invalid JSON, ``default()`` raises
  ``DefaultCredentialsError`` immediately and **does not** fall through to the
  metadata server.

That second point is the common migration surprise. Before the migration the
explicit path existed; after it, the file is gone. Whether the process ends up
on a managed identity depends on one comparison: is the missing path exactly
the Cloud SDK default path? If yes, discovery continues silently to the
metadata stage. If no, ``default()`` fails loudly and never reaches it.

Project ID resolution
---------------------

The project ID comes from a specific layer, not from a global lookup:

* ``service_account`` files: the ``project_id`` field in the file.
* ``authorized_user`` files: no project of their own; the Cloud SDK stage runs
  ``gcloud config get project``.
* Compute Engine: ``project/project-id`` from the metadata service.
* External accounts (workload identity federation): the audience contains a
  project *number*. ``get_project_id`` resolves it through Cloud Resource
  Manager only after scopes are available. Without scopes it returns ``None``
  and makes no HTTP request. A ``None`` result therefore means either "no scopes
  yet" or "not readable by this identity", not "no identity".

An explicit project always wins over whatever the credential reports:

* ``GOOGLE_CLOUD_PROJECT`` (or legacy ``GCLOUD_PROJECT``) becomes the returned
  project ID. It also short-circuits the deferred external-account lookup, so no
  Cloud Resource Manager request is made.
* ``quota_project_id`` (or ``GOOGLE_CLOUD_QUOTA_PROJECT``) is a separate
  channel. It becomes the ``x-goog-user-project`` header used for quota and
  billing. It does **not** change the returned project ID, the credential
  class, or the source evidence.

Keep those three values separate in every report:

============================  ============================================================
Value                         Question it answers
============================  ============================================================
Returned project ID           Which project will the client library default to?
Quota project / header        Which project is billed and limited?
Credential class and source   Which identity actually authenticated?
============================  ============================================================

Running the synthetic scenarios
-------------------------------

``scripts/adc_diagnostics.py`` runs each built-in scenario against synthetic files
in a temporary directory. gcloud and the metadata service are replaced by
recording stubs, so the script never reads the workstation's real ADC file,
never invokes gcloud, and never contacts a metadata endpoint::

    python scripts/adc_diagnostics.py
    python scripts/adc_diagnostics.py --format json
    python scripts/adc_diagnostics.py --scenario external_account_deferred

Each report contains:

* the returned project ID and quota project;
* the credential class, credential type, source evidence, and principal;
* an ordered event list covering file reads, scope attachment, quota
  application, and project lookups;
* an ordered probe list covering the SDK file existence check,
  ``gcloud config get project``, ``is_on_gce``, ``project/project-id``, the STS
  exchange, and the Cloud Resource Manager request.

The scenarios to compare for a migration report are:

``sdk_user_without_explicit_env`` and ``managed_vm_same_project``
    Both return ``shared-project-123456``. They differ in credential class,
    source evidence, and probes: user credentials need ``gcloud config get
    project``; VM credentials need ``is_on_gce`` and ``project/project-id``.

``explicit_distinct_missing``
    The explicit path is not the SDK default and the file is missing. The report
    shows a single ``file_read_failed`` event and no probes. This is terminal.

``explicit_same_sdk_missing``
    The explicit path is the SDK default and the file is missing. The report
    shows the SDK file check reporting ``absent`` with
    ``explicit_path_matches=True``, the Cloud SDK stage returning nothing, and
    discovery continuing to the metadata stage. This is the silent-fallback
    shape.

``external_account_deferred``
    The first project lookup is skipped because scopes are absent; after
    ``scope_attachment`` the report shows the STS exchange and the Cloud
    Resource Manager request. The returned project comes from the audience
    project number.

``external_account_explicit_project`` and ``external_account_quota_project``
    Compare these with ``external_account_deferred``: the explicit project
    changes only the returned value and removes the lookup; the quota project
    changes only the quota field and header while the lookup still happens.

``external_account_no_scopes`` and ``external_account_lookup_denied``
    Both return no project. In the first the lookup was skipped for lack of
    scopes; in the second the STS exchange succeeded and the Cloud Resource
    Manager request returned 403. The probe result distinguishes them.

Reading a report
----------------

Support can classify a case from three fields, in this order:

1. **Credential class and source.** If the class is
   ``google.auth.compute_engine.credentials.Credentials`` with source
   ``metadata server``, the process is on a managed identity. If the class is
   ``google.oauth2.credentials.Credentials`` with a Cloud SDK path as source, it
   is developer credentials. External accounts are
   ``google.auth.identity_pool.Credentials`` (or the AWS/pluggable variants).
2. **Which project lookup ran.** ``gcloud config get project`` implies the Cloud
   SDK stage. ``project/project-id`` implies the metadata stage. A Cloud
   Resource Manager request implies deferred external-account resolution. No
   probe at all with a returned project implies an explicit environment value.
3. **Whether a quota project was applied.** A non-``None`` quota project is
   evidence about billing, not about identity. It never explains a credential
   class or a returned project ID.

If all three say the same thing but the observed behavior differs from
expectation, the next step is to check whether the expected file still exists at
the exact path in ``GOOGLE_APPLICATION_CREDENTIALS`` and whether that path equals
the Cloud SDK default path. Those two facts decide whether a missing file is
terminal or a silent fallback.

Safe evidence to collect
------------------------

When a real environment must be described, collect only non-secret evidence:

* the output of ``google.auth.default()``'s second return value (project ID);
* ``credentials.__class__`` and ``credentials.get_cred_info()``, which contains
  the credential type, the *path* (not the contents) of the source file, and the
  principal;
* ``credentials.quota_project_id``;
* the names of the environment variables that are set, not their values;
* whether the path in ``GOOGLE_APPLICATION_CREDENTIALS`` equals the Cloud SDK
  default path.

Never collect file contents, refresh tokens, private keys, client secrets,
access tokens, or the output of ``gcloud auth print-access-token``.
