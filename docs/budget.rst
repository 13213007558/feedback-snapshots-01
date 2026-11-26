.. _budget-chapter:

Work budget
===========

The comment pipeline can spend arbitrary time on pathological input while
parsing, sanitizing and linkifying.  A :class:`bleach.budget.Budget` is a
**single-run** meter shared by all three rings of one piece of content:

``parse``
   HTML tokenizing and tree construction (see
   :class:`bleach.html5lib_shim.BleachHTMLParser`).

``clean``
   The sanitizer filter stream (see
   :class:`bleach.sanitizer.BleachSanitizerFilter`).

``linkify``
   Optional link/email/anchor transformations (see
   :class:`bleach.linkifier.LinkifyFilter`).

Budgeting is opt-in.  The default (``budget=None``) keeps Bleach's
historical unlimited behaviour and output.

Metering rules
--------------

Work is charged to one shared unit pool:

* **nodes** -- each token/node event costs ``node_cost`` (default ``1``),
  and each attribute costs ``attribute_cost`` (default ``1``);
* **text** -- one unit per character of character/comment data
  (``character_cost``, default ``1``);
* **transforms** -- every extra transformation costs ``transform_cost``
  (default ``10``): each URL/email match converted by
  :class:`~bleach.linkifier.LinkifyFilter`, each existing ``<a>`` run through
  callbacks, and each CSS sanitization call.

Pass an integer limit for the defaults, or a configured
:class:`~bleach.budget.Budget`.  ``Budget(limit=None)`` meters without
enforcing, which is useful for measuring a baseline before choosing a quota.

Handling exhaustion
-------------------

When a charge pushes cumulative spend strictly above the limit,
:class:`bleach.budget.BudgetExceeded` is raised.  Its ``stage`` attribute
names the ring that detected the overrun, and it carries the per-stage
spend and raw counts:

.. code-block:: python

   from bleach.sanitizer import Cleaner
   from bleach.linkifier import LinkifyFilter
   from bleach.budget import BudgetExceeded

   cleaner = Cleaner(
       tags={"p", "a"},
       filters=[LinkifyFilter],
       budget=20_000,
   )

   try:
       html = cleaner.clean(user_comment)
   except BudgetExceeded as exc:
       # exc.stage is "parse", "clean" or "linkify"
       log.warning("comment rejected: %s (used %s/%s)",
                   exc.stage, exc.used, exc.limit)
       return DEFAULT_COMMENT

Because :meth:`~bleach.sanitizer.Cleaner.clean` renders the stream eagerly,
an overrun propagates out of the call: no truncated or partially processed
string is returned as if it were the complete result.

Reuse after a failure
---------------------

The budget is a per-run meter.  :class:`~bleach.sanitizer.Cleaner` and
:class:`~bleach.linkifier.Linker` reset it at the start of every call, so a
document that trips the limit does not poison later requests -- keep using
the same configured entry point:

.. code-block:: python

   cleaner = Cleaner(budget=5_000, filters=[LinkifyFilter])

   for comment in comment_stream:
       try:
           publish(cleaner.clean(comment))
       except BudgetExceeded:
           reject(comment)

A standalone :func:`bleach.linkify` / :class:`~bleach.linkifier.Linker`
accepts the same ``budget=`` argument, and the module-level
:func:`bleach.clean` accepts it too.  ``work_budget=`` is an alias.

Local verification
------------------

The repository contains a runnable end-to-end check with two ordinary local
documents under ``verification/``: a long plain-text comment that succeeds
without transformations and a node/link-heavy comment whose parsing and
cleaning fit the manually lowered quota until link transformations are
counted.  It records every stage and the final output:

.. code-block:: sh

   .venv/bin/python verification/verify_budget.py

See ``verification/verification_record.md`` for a captured run.
