Bounded Policy Diff
===================

:func:`compare_lvs_models` compares the signing relations of two LVS models
inside a finite, caller-supplied scope.  It answers a review question such as
"does the new model allow any signing relation that the old one did not?",
and emits a concrete data name, signer name, and certificate path for every
new relation it reports.

Scope
-----

The scope has four explicit limits:

* a finite set of component candidates used for pattern variables;
* a maximum name length;
* a maximum certificate-path depth from the signer to a trust anchor;
* an evaluation budget and a candidate-name cap.

Candidate names are generated from the compiled rule trees, so only names
that can match some rule are considered.  The tool reports one of:

``NEW_RELATION_FOUND``
    At least one effective relation exists in the new model and not in the old
    model.  The first example is the shortest one in the declared scope.

``REMOVED_RELATION_FOUND``
    The old model allows a relation that the new model does not.

``NO_NEW_RELATION_IN_SCOPE``
    Every candidate pair in the declared scope was examined and no difference
    was found.  This is scope exhaustion, not a proof of equivalence.

``BUDGET_EXHAUSTED``
    The evaluation or name budget ran out.  No absence claim is made.

``UNKNOWN``
    A user function has no analysable contract, or a witness could not be
    confirmed by the real :class:`Checker`.  Observed true results are never
    generalised over other names.

``NO_TRUST_ANCHOR_IN_SCOPE`` / ``NO_TRUST_ROOT``
    The effective-relation question cannot be answered with the given bounds,
    for example because no generated name reaches a trust root.

Effective relations
-------------------

A relation is counted only when both conditions hold:

1. :meth:`Checker.check` allows the signer to sign the data name; and
2. the signer reaches a trust root within the certificate-depth bound.

The certificate path is reported hop by hop and every hop is re-checked with a
real :class:`Checker`.  Callers can pass ``check_trust_anchor`` to restrict
which rule-root names are actually configured as deployment anchors.

User functions
--------------

The search only uses a :class:`FnContract` supplied by the caller.  If a model
uses a function without a contract, constraints that call it evaluate to
``unknown``; the report lists the function and does not infer its behaviour
from a single successful Checker execution.  ``EQ_CONTRACT`` and
``EQ_TYPE_CONTRACT`` encode the two documented python-ndn built-ins.

CLI
---

The same analysis is available as ``pyname diff-lvs``::

    pyname diff-lvs old.lvs new.lvs \
        --component site --component root --component KEY \
        --max-name-len 5 --max-cert-depth 3 \
        --data-rule '#post' --contract eq_type

Use ``--json`` for a machine-readable report.
