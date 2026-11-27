.. _checkpoints:

Event Checkpoints and Recovery
==============================

When `persistent`_ mode is enabled, Flower stores the events state as
versioned checkpoints and decides which checkpoint to use before any query can
read it. The same admitted state feeds the task map, the search index and the
dashboard counters, so ``/tasks``, ``/tasks/datatable`` and ``/api/tasks``
always describe one generation.

.. _persistent: config.html#persistent

Storage Layout
--------------

A checkpoint generation lives below the configured `db`_ path::

    flower.checkpoints/
        gen-000000000001/
            manifest.json
            events.pkl
            counters.json
        gen-000000000002/       # rejected: manifest.json is missing
            events.pkl
            counters.json.tmp-998
    flower.recovery/
        latest.json
        recovery.jsonl

`manifest.json` is written last. It records the format name and version, the
generation number, the creation time, the task and counter totals, and the
size and SHA-256 of each fragment. A directory without a manifest is a save
that never finished; it is reported and skipped, never merged.

Legacy storage, the flat dbm shelf that older Flower versions wrote at the
`db`_ path (``flower``, ``flower.db``, ``flower.dat``/``.dir`` and so on), is
still recognized. It is used only when no complete generation passes
admission, and a warning notes that the next save publishes a versioned
checkpoint.

Admission
---------

Startup evaluates every candidate in this order:

1. each generation directory, newest first;
2. staging artifacts left beside or inside a generation;
3. the legacy dbm shelf.

A generation is admitted only if the manifest is present and valid, its
format version meets `checkpoint_min_format_version`_, every declared fragment
is present with the recorded size and digest, the payload loads, and the
manifest totals match the payload. Anything else is rejected with a reason.
The selected source is the highest admitted generation. If none is admitted,
the legacy shelf is used when `checkpoint_allow_legacy`_ allows it; otherwise
Flower opens an explicit empty state. A corrupt or partial candidate is never
renamed, deleted or mixed with another generation.

.. _checkpoint_min_format_version: config.html#checkpoint-min-format-version
.. _checkpoint_allow_legacy: config.html#checkpoint-allow-legacy

Recovery Record
---------------

Every startup writes the decision to ``<db>.recovery/latest.json`` and appends
the same object to ``<db>.recovery/recovery.jsonl``. The record contains the
admission policy, every candidate with its status and reason, the selected
source, and a ``retrieval`` summary describing what the query paths can see:
task count, indexed task count, counter total, task states and a bounded
sample of task ids.

.. code-block:: json

    {
      "schema": "flower.recovery/1",
      "policy": {"min_format_version": 0, "allow_legacy": true},
      "candidates": [
        {"source": "generation", "generation": 2, "status": "rejected",
         "reason": "manifest is missing: the generation was never completed"},
        {"source": "generation", "generation": 1, "status": "admitted",
         "reason": "complete and admitted", "format_version": 1,
         "task_count": 3, "counter_total": 7,
         "fragments": {"expected": 2, "present": 2}}
      ],
      "selected": {
        "source": "generation", "generation": 1, "status": "admitted",
        "reason": "highest admitted generation"
      },
      "retrieval": {
        "open": true, "task_count": 3, "indexed_task_count": 3,
        "counter_total": 7, "states": {"FAILURE": 1, "SUCCESS": 2}
      }
    }

Demonstration
-------------

``python -m flower.recovery_demo`` runs the whole sequence in a temporary
directory and prints each startup decision and the queries that follow it:

1. an empty directory opens an empty state;
2. a normal save publishes generation 1, and the next startup admits it;
3. a save that wrote only part of a generation leaves generation 2 without a
   manifest, and the next startup keeps generation 1;
4. a startup with ``--checkpoint-min-format-version=2`` rejects generation 1
   as too old and opens an empty state.

Use ``--keep`` to inspect the directory, or ``--dir`` to run in a path you
choose.

.. _db: config.html#db
