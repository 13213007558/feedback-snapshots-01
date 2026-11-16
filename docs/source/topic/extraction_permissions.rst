.. _topic_extraction_permissions:

Extraction permissions and authorization
****************************************

PDF encryption and PDF permissions answer two different questions. Encryption
controls who can read the bytes. The ``/P`` integer in the encryption
dictionary is a *declaration by the document producer* about what readers
should be allowed to do. Neither of them is an authorization decision made by
your application.

pdfminer.six historically errs on the side of being a parser: it decrypts,
extracts, and logs a warning when ``/P`` forbids extraction. This page
describes exactly where that happens, and how to opt into an enforcing,
auditable contract.

Three separate layers
=====================

Keep these layers apart in your own code:

``PDF permission declaration``
    The ``/P`` bits in the document's ``/Encrypt`` dictionary. pdfminer
    exposes them as ``PDFDocument.is_extractable`` (bit 16),
    ``is_printable`` (bit 4) and ``is_modifiable`` (bit 8), plus the raw value
    in ``PDFDocument.permissions``. These bits are *claimed by the file*. For
    revisions 5 and 6 the bits in ``/P`` are not authenticated; pdfminer
    decrypts the ``/Perms`` entry with the file key and records the result in
    ``PDFDocument.perms_verified``. A ``False`` here means ``/P`` was altered
    after the file was produced and must not be trusted.

``Password possession``
    A correct user or owner password proves access to the cipher, nothing
    more. ``PDFDocument.password_role`` records which one succeeded
    (``"user"`` or ``"owner"``). An owner password does **not** turn a
    restrictive ``/P`` into an application authorization. Treat the role as an
    audit fact, not as a permit.

``Application authorization``
    Your application's decision that this document may be used for text
    extraction, e.g. a review workflow, a legal hold, or a signed request.
    This must be explicit, scoped to named documents, and recorded. In
    pdfminer.six this is :class:`pdfminer.pdfpage.ExtractionPolicy`.

What each entry point actually does
===================================

All public extraction paths funnel through ``PDFPage.get_pages``, except the
composable API where you call ``PDFPage.create_pages`` and
``PDFPageInterpreter`` yourself.

.. list-table::
   :header-rows: 1
   :widths: 42 22 36

   * - Entry point
     - Enforces ``/P``?
     - Behavior when extraction is denied
   * - ``extract_text``
     - No, unless opted in
     - Logs a warning, returns text
   * - ``extract_text_to_fp``
     - No, unless opted in
     - Logs a warning, writes text
   * - ``extract_pages``
     - No, unless opted in
     - Logs a warning, yields pages
   * - ``PDFPage.get_pages`` (default)
     - No
     - Logs a warning, yields pages
   * - ``get_pages(check_extractable=True)``
     - Yes
     - Raises ``PDFTextExtractionNotAllowed``
   * - ``get_pages(extraction_policy=...)``
     - Yes
     - Raises unless a scoped grant exists
   * - ``PDFPage.create_pages`` + interpreter
     - No, never
     - No check at all
   * - ``tools/pdf2txt.py``
     - No
     - Logs a warning, writes text
   * - ``tools/dumppdf.py``
     - No
     - Dumps objects without any check

Two consequences are easy to miss:

* ``extract_text_to_fp`` used to accept arbitrary ``**kwargs`` and silently
  ignore them, so ``check_extractable=True`` looked like it worked while text
  was still written. It is now an explicit parameter, and unknown keyword
  arguments raise :class:`pdfminer.pdfexceptions.PDFValueError`.
* The composable API never consulted ``/P``. If your application uses
  ``PDFPage.create_pages`` directly, you are responsible for calling
  ``ExtractionPolicy.check`` (or inspecting ``doc.is_extractable``) yourself.

Enforcing by default in your backend
====================================

Use ``ExtractionPolicy`` in every extraction path:

.. code-block:: python

    from pdfminer.high_level import extract_pages
    from pdfminer.pdfpage import ExtractionPolicy

    policy = ExtractionPolicy()          # respects the document's /P bits
    for page in extract_pages(path, extraction_policy=policy):
        ...

``extract_text`` and ``extract_text_to_fp`` accept the same
``extraction_policy`` keyword.

The forensic exception
======================

Sometimes the business has independent authorization to extract despite
``/P``: incident response, litigation, or a documented review workflow. Model
that as a grant that names the exact files it covers, and keep the reason:

.. code-block:: python

    import hashlib
    from pdfminer.high_level import extract_text
    from pdfminer.pdfpage import ExtractionPolicy

    with open(path, "rb") as fp:
        digest = hashlib.sha256(fp.read()).hexdigest()

    policy = ExtractionPolicy(
        [digest],
        granted=True,
        grant_reason="SEC-2026-11-17: review request approved by legal",
    )
    text = extract_text(path, extraction_policy=policy)

The grant is keyed by the SHA-256 of the PDF bytes, so the same policy object
cannot authorize any other document. Computing that digest reads the file
once more; for very large PDFs, compute it once during ingestion and store it
alongside the document. It is not a process-wide switch, it is
not stored in a module global, and it never mutates ``PDFDocument``. A grant
without named digests, or without a reason, raises ``PDFValueError``.

Auditing a decision
===================

Bind the policy to the parsed document and export the record. The record says
which layer decided, the document digest, the declared bits, the password
role, and whether ``/Perms`` was verified:

.. code-block:: python

    import hashlib
    import json
    from pdfminer.pdfdocument import PDFDocument
    from pdfminer.pdfpage import ExtractionPolicy
    from pdfminer.pdfparser import PDFParser

    with open(path, "rb") as fp:
        digest = hashlib.sha256(fp.read()).hexdigest()

    policy = ExtractionPolicy([digest], granted=True, grant_reason="case 42")

    with open(path, "rb") as fp:
        doc = PDFDocument(PDFParser(fp), password="")
        decision = policy.bind(doc, digest)
        decision.check(path)             # raises if not allowed
        audit = decision.audit_record(action="review.extract")

    log.info("extraction", extra={"audit": json.dumps(audit)})

For a granted forensic extraction of
``samples/contrib/issue-00352-asw-oct96-p41.pdf`` (``/P = -1340``, so text
extraction is denied) the record is::

    {
      "action": "extract_text",
      "allowed": true,
      "application_grant": true,
      "decided_by": "application_grant",
      "document_encrypted": true,
      "document_sha256": "4a73f2d26fa6e7573435c010ddffb9be54eb944f13b8a37ec78e5b0e20026f13",
      "grant_reason": "SEC-2026-11-17: review request approved by legal",
      "password_role": "user",
      "pdf_permission_extract": false,
      "permission_bits": 4294965956,
      "perms_verified": null
    }

For the unauthorized path ``check`` raises before any page is produced, so no
body text reaches the caller. The same policy used on an unrelated document
reports ``"decided_by": "pdf_permission"`` and ``"allowed": false``.

Integrity checks that matter
============================

* ``PDFDocument.permissions`` exposes ``/P`` normalized to an unsigned
  32-bit value (so a file that stores ``-1340`` reports ``4294965956``), or
  ``None`` for an unencrypted document.
* For ``/V 5`` documents, ``PDFDocument.perms_verified`` is ``True`` when the
  decrypted ``/Perms`` entry agrees with ``/P``, ``False`` when they disagree,
  and ``None`` for revisions that do not carry a verifiable ``/Perms`` entry.
  Check it before trusting ``is_extractable`` on an AES-256 document.
* A wrong password raises ``PDFPasswordIncorrect``; it never degrades to an
  unauthenticated extraction.

Recommended defaults
====================

* Application backends should pass ``extraction_policy=ExtractionPolicy()``
  on every extraction call, including batch jobs, so that a missing argument
  is a code review finding rather than a silent bypass.
* Do not add a module-level or environment-variable "allow all" switch.
  Grants name document digests and carry a reason.
* Log ``audit_record`` for both allowed and denied decisions; the denied path
  is where you detect attempts to extract restricted documents.
* If you use the composable API, perform the same policy check before
  constructing a ``PDFPageInterpreter``.
