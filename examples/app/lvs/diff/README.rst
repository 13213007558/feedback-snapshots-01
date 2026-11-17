Bounded LVS policy diff
=======================

This example shows a bounded comparison of two Light VerSec models.

``model-old.lvs`` and ``model-new.lvs`` differ only in the user-attribution
constraint on ``#post``: the old model allows only ``alice``, while the new
model allows ``alice`` or ``bob``.  ``model-equiv.lvs`` expresses the new
relation with a different syntax (two rules with explicit values) and should
show no difference in the same scope.

Run the comparison:

.. code-block:: console

    pyname diff-lvs model-old.lvs model-new.lvs \
        --component site --component root --component post \
        --component author --component KEY --component v \
        --component alice --component bob --component carol \
        --max-name-len 5 --max-cert-depth 3 --data-rule '#post'

The shortest new relation reported is::

    /site/post/bob/post  <-  /site/author/bob/KEY/v  <-  /site/root/KEY/v

Every hop is re-checked with the real :class:`Checker`.  The result is a
witness inside the declared finite scope, not a proof that the models differ
for all names.  Conversely, the comparison of ``model-new.lvs`` and
``model-equiv.lvs`` reports ``NO_NEW_RELATION_IN_SCOPE`` only after the
candidate space has been exhausted; it still does not claim semantic
equivalence over all possible names.

Exit codes: ``0`` no new relation, ``1`` new relation, ``2`` removed
relation, ``3`` inconclusive (budget, unknown function, missing anchor),
``4`` input error.
