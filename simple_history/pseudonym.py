"""
Controlled pseudonymization of ``history_user`` links.

When a person leaves an organization, the historical rows that reference their
account must stop pointing at that account, while auditors still need to see that
the same anonymous subject performed several operations. This module implements
that as a *one-way*, *keyed* pseudonymization:

* every historical model gains a ``history_user_pseudonym`` character field;
* severing a link clears ``history_user_id`` and stores a stable, keyed
  pseudonym (an HMAC-SHA256 digest) instead;
* the pseudonym is never reversible from the database alone, and the read paths
  (``history_user`` and the admin history view) never fall back to the account;
* rows that already carry a pseudonym are never touched again, so repeating a
  batch is idempotent and cannot restore the original association.

The module deliberately separates *processing* from *reading*: a batch is
explicit about which rows it may change through a watermark, and ``as_of`` or
ordinary history queries only ever interpret what is stored in the row.
"""
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.db.models import ForeignKey, Q

from .exceptions import InvalidPseudonymizationIdentity, PseudonymizationConflict

PSEUDONYM_FIELD_NAME = "history_user_pseudonym"
PSEUDONYM_MAX_LENGTH = 64
PSEUDONYM_SCHEME = "hmac-sha256"

DEFAULT_SECRET_SETTING = "SIMPLE_HISTORY_PSEUDONYM_SECRET"


def get_pseudonym_secret():
    """
    Return the secret used to derive pseudonyms.

    The secret is read from ``SIMPLE_HISTORY_PSEUDONYM_SECRET`` so that it lives
    outside the database and can be rotated by re-pseudonymizing with a new
    namespace. Without it, pseudonyms cannot be derived at all; the module
    intentionally refuses to invent one.
    """
    secret = getattr(settings, DEFAULT_SECRET_SETTING, None)
    if not secret:
        raise ImproperlyConfigured(
            f"{DEFAULT_SECRET_SETTING} must be configured to pseudonymize "
            "historical user links."
        )
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return secret


def normalize_identity(value) -> str:
    """
    Normalize a raw identity (a primary key) into the stable string that is fed
    into the keyed digest.

    Bytes are treated as an already-serialized identity; everything else uses
    its string form. Empty, missing or whitespace-only identities are rejected,
    because deriving a pseudonym for them would silently merge distinct subjects.
    """
    if value is None:
        raise InvalidPseudonymizationIdentity("Cannot pseudonymize a missing identity.")
    if isinstance(value, bytes):
        if not value.strip():
            raise InvalidPseudonymizationIdentity(
                "Cannot pseudonymize an empty identity."
            )
        return value.hex()
    if isinstance(value, (list, tuple, dict, set)):
        raise InvalidPseudonymizationIdentity(
            "A single scalar identity is required, not a collection."
        )
    text = str(value)
    if not text.strip():
        raise InvalidPseudonymizationIdentity("Cannot pseudonymize an empty identity.")
    return text


def pseudonym_for(
    identity,
    *,
    namespace="default",
    secret=None,
    length=PSEUDONYM_MAX_LENGTH,
):
    """
    Derive the pseudonym for ``identity``.

    The digest is keyed with ``secret`` (defaults to the configured setting) and
    bound to ``namespace``, so the same person can receive different pseudonyms
    in different audit scopes and an old pseudonym cannot be re-derived without
    the key. The result is hexadecimal, hence safe to store and display.
    """
    if secret is None:
        secret = get_pseudonym_secret()
    elif isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not namespace or not str(namespace).strip():
        raise InvalidPseudonymizationIdentity("A pseudonym namespace is required.")
    message = (
        f"{PSEUDONYM_SCHEME}\x00{namespace}\x00{normalize_identity(identity)}"
    ).encode("utf-8")
    digest = hmac.new(secret, message, hashlib.sha256).hexdigest()
    if length is None or length >= len(digest):
        return digest
    if length <= 0:
        raise ValueError("Pseudonym length must be positive.")
    return digest[:length]


def generate_pseudonym_secret():
    """Convenience helper to create a strong secret for configuration."""
    return secrets.token_urlsafe(48)


def pseudonym_label(pseudonym, *, prefix="pseudonym"):
    """
    Return the public, human-readable label for a stored pseudonym.

    Only a short, non-secret slice of the digest is shown, so the label is
    stable across audit entries without exposing enough material to help an
    offline reversal attempt. ``None`` stays ``None``.
    """
    if not pseudonym:
        return None
    return f"{prefix}:{pseudonym[:12]}"


@dataclass(frozen=True)
class PseudonymizationResult:
    """Summary of one pseudonymization batch."""

    model: Any
    pseudonym: str
    pseudonymized: int
    already_pseudonymized: int
    watermark: Any
    cutoff: Any

    @property
    def processed(self):
        return self.pseudonymized + self.already_pseudonymized


def _history_manager(model):
    from .utils import get_history_manager_for_model

    return get_history_manager_for_model(model)


def _identity_attname(history_model):
    """
    Return the attribute that stores the identity of the acting user on the
    historical rows of a model.

    For FK-tracked users this is ``history_user_id``; for manually tracked users
    it is whatever field the project supplied. Both are handled the same way.
    """
    return history_model._meta.get_field("history_user_id").attname


def _watermark_value(history_model, watermark):
    """Normalize ``watermark`` into a value of the history primary key field."""
    pk_field = history_model._meta.pk
    if watermark is None:
        return None
    return pk_field.to_python(watermark)


def pseudonymization_scope(model, *, watermark=None, cutoff=None, base_queryset=None):
    """
    Build the queryset of historical rows that a batch is allowed to process.

    ``watermark`` is an exclusive upper bound on ``history_id``: rows created
    after the watermark are *not* touched by the batch. ``cutoff`` is an
    inclusive upper bound on ``history_date``. ``base_queryset`` narrows the
    scope further (for example to one object's history manager); it must belong
    to the historical model. Passing none of these processes all rows, which is
    useful for a first full pass.
    """
    if base_queryset is not None:
        qs = base_queryset.all()
        history_model = qs.model
    else:
        history_model = _history_manager(model).model
        qs = history_model._default_manager.all()
    if watermark is not None:
        qs = qs.filter(pk__lt=_watermark_value(history_model, watermark))
    if cutoff is not None:
        qs = qs.filter(history_date__lte=cutoff)
    return qs


def identity_kind(history_model):
    """
    Return ``"foreign_key"`` or ``"external"`` for a historical model.

    The distinction matters when a caller supplies raw identity strings: the
    foreign-key field can only hold values of its related model's primary key
    type, while an externally managed identity field is free-form text.
    """
    field = history_model._meta.get_field("history_user_id")
    return "foreign_key" if isinstance(field, ForeignKey) else "external"


def _user_filter(history_model, users, identities):
    """
    Build the ``Q`` object selecting rows that belong to any of the given
    identities.

    ``users`` may contain user instances; their primary keys are added to
    ``identities``. The ``Q`` is expressed on the raw identity attribute so it
    works for both FK-tracked and manually tracked users.
    """
    identity_attname = _identity_attname(history_model)
    values = list(identities)
    for user in users:
        values.append(user.pk)
    if not values:
        raise InvalidPseudonymizationIdentity(
            "At least one user or identity is required."
        )
    query = Q()
    for value in values:
        if value is None:
            raise InvalidPseudonymizationIdentity(
                "Cannot pseudonymize a missing identity."
            )
        query |= Q(**{identity_attname: value})
    return query


def _pseudonym_attname(history_model):
    return history_model._meta.get_field(PSEUDONYM_FIELD_NAME).attname


def _as_list(values, single):
    """Combine an iterable and a single optional value into one list."""
    result = list(values or ())
    if single is not None:
        result.append(single)
    return result


def _resolve_pseudonym_subject(users, identities, subject):
    """
    Return the stable token the pseudonym is derived from.

    An explicit ``subject`` is required when several different identities are
    severed in one batch; otherwise deriving from one of them would invent an
    association the caller never asserted.
    """
    if not users and not identities:
        raise InvalidPseudonymizationIdentity(
            "A user or identity is required to pseudonymize history."
        )
    candidates = [user_obj.pk for user_obj in users]
    candidates.extend(identities)
    if subject is not None:
        return subject
    distinct = {str(candidate) for candidate in candidates}
    if len(distinct) != 1:
        raise InvalidPseudonymizationIdentity(
            "Pass an explicit subject when severing several different "
            "identities in one batch."
        )
    return candidates[0]


def anonymize_history_user(
    model,
    *,
    user=None,
    users=None,
    identity=None,
    identities=None,
    subject=None,
    namespace="default",
    secret=None,
    watermark=None,
    cutoff=None,
    using=None,
    queryset=None,
    dry_run=False,
):
    """
    Sever the historical rows of ``model`` from one or more user accounts while
    keeping a stable pseudonym for each anonymous subject.

    The rows to sever are selected by ``user``/``users`` (Django accounts) or
    ``identity``/``identities`` (externally managed identifiers). The pseudonym
    itself is derived from ``subject`` -- the stable identifier of the anonymous
    subject. When ``subject`` is omitted, a single account or identity doubles as
    the subject. Pass ``subject`` together with several identities when one
    person is known under more than one external identifier; they then share one
    pseudonym without silently merging unrelated people.

    The operation is a single transaction. It is idempotent: rows that already
    contain the derived pseudonym are counted, not rewritten. Rows that already
    contain a *different* pseudonym raise :class:`PseudonymizationConflict`,
    because merging two anonymous subjects would be a false audit trail.

    ``watermark`` restricts the batch to rows with a primary key strictly lower
    than the given history ID, giving an explicit boundary for rows created
    while processing is happening. ``cutoff`` does the same for ``history_date``
    (inclusive). Neither the source model nor any user row is modified.

    :param model: The history-tracked model class.
    :param user: A user instance to sever.
    :param users: An iterable of user instances for the *same* subject.
    :param identity: A raw identity value, used for external identity systems.
    :param identities: An iterable of raw identity values for the same subject.
    :param subject: Optional stable subject token used to derive the pseudonym.
    :param namespace: A scope separator for the keyed digest.
    :param secret: Override for the configured secret (mainly for rotation).
    :param watermark: Exclusive upper bound on the history primary key.
    :param cutoff: Inclusive upper bound on ``history_date``.
    :param using: Optional database alias.
    :param queryset: Optional historical queryset limiting the rows considered.
    :param dry_run: Only count the rows that would be processed.
    :return: A :class:`PseudonymizationResult`.
    """
    history_manager = _history_manager(model)
    history_model = history_manager.model
    if queryset is not None and queryset.model is not history_model:
        raise InvalidPseudonymizationIdentity(
            "The queryset must belong to this model's historical model."
        )
    db = using or history_manager.db

    identity_attname = _identity_attname(history_model)
    supplied_users = _as_list(users, user)
    supplied_identities = _as_list(identities, identity)

    if supplied_identities and identity_kind(history_model) == "foreign_key":
        raise InvalidPseudonymizationIdentity(
            "This model tracks users with a foreign key; pass a user, not a raw "
            "identity."
        )

    pseudonym_subject = _resolve_pseudonym_subject(
        supplied_users, supplied_identities, subject
    )
    pseudonym = pseudonym_for(
        pseudonym_subject, namespace=namespace, secret=secret
    )

    scoped = pseudonymization_scope(
        model, watermark=watermark, cutoff=cutoff, base_queryset=queryset
    ).using(db)
    identity_qs = scoped.filter(
        _user_filter(history_model, supplied_users, supplied_identities)
    )
    pseudonym_attname = _pseudonym_attname(history_model)

    # Rows reachable through the derived pseudonym have already been severed
    # (possibly by an earlier run of the same batch). They are counted, never
    # rewritten, which makes repeating a batch a no-op.
    already_qs = scoped.filter(**{pseudonym_attname: pseudonym})

    # An identity-bearing row that already carries a *different* pseudonym was
    # assigned to another anonymous subject. Refuse to merge the two.
    conflicting = identity_qs.exclude(
        Q(**{f"{pseudonym_attname}__isnull": True})
        | Q(**{pseudonym_attname: ""})
        | Q(**{pseudonym_attname: pseudonym})
    )
    if conflicting.exists():
        raise PseudonymizationConflict(
            "Some historical rows already contain a different pseudonym; "
            "refusing to merge anonymous subjects."
        )

    to_process = identity_qs.exclude(**{pseudonym_attname: pseudonym})
    already = already_qs.count()
    count = to_process.count()

    watermark_value = _watermark_value(history_model, watermark)
    cutoff_value = cutoff

    if dry_run:
        return PseudonymizationResult(
            model=model,
            pseudonym=pseudonym,
            pseudonymized=count,
            already_pseudonymized=already,
            watermark=watermark_value,
            cutoff=cutoff_value,
        )

    with transaction.atomic(using=db):
        updated = to_process.update(
            **{
                identity_attname: None,
                pseudonym_attname: pseudonym,
            }
        )
    return PseudonymizationResult(
        model=model,
        pseudonym=pseudonym,
        pseudonymized=updated,
        already_pseudonymized=already,
        watermark=watermark_value,
        cutoff=cutoff_value,
    )
