.. _api_authorization:

.. py:module:: pynetdicom.authorization

C-MOVE Authorisation (:mod:`pynetdicom.authorization`)
=======================================================

Optional destination authorisation for the C-MOVE service. An
:class:`~pynetdicom.ae.ApplicationEntity` may be assigned a policy using its
:attr:`~pynetdicom.ae.ApplicationEntity.move_authorization` property.

A C-MOVE SCP makes two independent privileged decisions: whether the
requesting identity may query the archive, and whether a **new** association
may be opened with the *Move Destination* in order to send the matching SOP
Instances. A destination approval may also be withdrawn while a C-MOVE
operation is in progress. Policies implementing the
:class:`MoveAuthorization` protocol are consulted at each of these stages and
again for every C-STORE sub-operation, so a withdrawn approval stops any
remaining datasets from being sent.

Datasets that were never sent are reported in the final C-MOVE response using
the *Number of Remaining Sub-operations* parameter, separately from genuine
C-STORE failures reported by *Number of Failed Sub-operations*.

.. currentmodule:: pynetdicom.authorization

.. autosummary::
   :toctree: generated/

   InMemoryMoveAuthorization
   MoveApproval
   MoveAuthorization
   query_identity
