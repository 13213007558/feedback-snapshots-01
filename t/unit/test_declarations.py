from __future__ import annotations

import pytest

from kombu import Connection, Exchange, Queue
from kombu.declarations import (
    ALL_ENTITY_KINDS, BINDING_ENTITY, EXCHANGE_ENTITY, QUEUE_ENTITY,
    DeclarationPolicy,
)
from kombu.entity import binding
from kombu.exceptions import DeclarationNotAllowed


class test_DeclarationPolicy:

    def test_default_allows_every_entity_kind(self):
        policy = DeclarationPolicy()
        assert policy.allowed == ALL_ENTITY_KINDS
        assert policy.permits(Exchange('events'))
        assert policy.permits(Queue('events'))
        assert policy.permits(binding(Exchange('events')))
        policy.check(Queue('events'))

    def test_empty_policy_forbids_everything(self):
        policy = DeclarationPolicy([])
        assert policy.allowed == frozenset()
        with pytest.raises(DeclarationNotAllowed, match='queue'):
            policy.check(Queue('events'))
        with pytest.raises(DeclarationNotAllowed, match='exchange'):
            policy.check(Exchange('events'))
        with pytest.raises(DeclarationNotAllowed, match='binding'):
            policy.check(binding(Exchange('events')))

    def test_publish_only_policy_allows_only_exchanges(self):
        policy = DeclarationPolicy([EXCHANGE_ENTITY])
        assert policy.permits(Exchange('events'))
        assert not policy.permits(Queue('events'))
        assert not policy.permits(binding(Exchange('events')))

    @pytest.mark.parametrize('kind', [
        EXCHANGE_ENTITY, QUEUE_ENTITY, BINDING_ENTITY,
    ])
    def test_each_entity_kind_is_recognized(self, kind):
        policy = DeclarationPolicy([kind])
        assert policy.allowed == frozenset({kind})

    def test_equality_and_repr(self):
        assert DeclarationPolicy([EXCHANGE_ENTITY]) == \
            DeclarationPolicy([EXCHANGE_ENTITY])
        assert DeclarationPolicy([EXCHANGE_ENTITY]) != \
            DeclarationPolicy([QUEUE_ENTITY])
        assert hash(DeclarationPolicy([EXCHANGE_ENTITY])) == \
            hash(DeclarationPolicy([EXCHANGE_ENTITY]))
        assert "['exchange']" in repr(DeclarationPolicy([EXCHANGE_ENTITY]))


class test_ConnectionDeclarationPolicy:

    def test_default_connection_has_no_restriction(self):
        connection = Connection('memory://')
        assert connection.declaration_policy is None

    def test_policy_instance_is_kept(self):
        policy = DeclarationPolicy([EXCHANGE_ENTITY])
        connection = Connection('memory://', declaration_policy=policy)
        assert connection.declaration_policy is policy

    def test_iterable_is_normalized_to_policy(self):
        connection = Connection(
            'memory://', declaration_policy=[EXCHANGE_ENTITY])
        assert connection.declaration_policy == \
            DeclarationPolicy([EXCHANGE_ENTITY])

    def test_policy_survives_clone_and_pool(self):
        policy = DeclarationPolicy([EXCHANGE_ENTITY])
        connection = Connection('memory://', declaration_policy=policy)
        assert connection.clone().declaration_policy == policy
        pool = connection.Pool(limit=1)
        with pool.acquire() as pooled:
            assert pooled.declaration_policy == policy

    def test_policy_survives_pickle_roundtrip(self):
        import pickle

        policy = DeclarationPolicy([EXCHANGE_ENTITY])
        connection = Connection('memory://', declaration_policy=policy)
        restored = pickle.loads(pickle.dumps(connection))
        assert restored.declaration_policy == policy

    def test_policy_survives_switch(self):
        policy = DeclarationPolicy([EXCHANGE_ENTITY])
        connection = Connection('memory://', declaration_policy=policy)
        connection.switch('memory://')
        assert connection.declaration_policy == policy
