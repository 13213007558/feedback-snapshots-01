.. _serialization_and_migration:

Serialization and Migration
===========================

python-doubleratchet uses `pydantic <https://pydantic-docs.helpmanual.io/>`_ for serialization internally. All classes that support serialization offer a property called ``model`` which returns the internal state of the instance as a pydantic model, and a method called ``from_model`` to restore the instance from said model. However, while these properties/methods are available for public access, migrations can't automatically be performed when working with models directly. Instead, the property ``json`` is provided, which returns the internal state of the instance a JSON-friendly Python dictionary, and the method ``from_json``, which restores the instance *after* performing required migrations on the data. Unless you have a good reason to work with the models directly, stick to the JSON serialization APIs.

Migration from pre-stable
-------------------------

Migration from pre-stable is provided, however, since the class hierarchy and serialization concept has changed, only whole Double Ratchet objects can be migrated to stable. Use the ``from_json`` method as usual.

Safe, verifiable migration workflow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Field-level translation alone is not enough to keep a live session usable: out-of-order messages that have not
been received yet are protected by *skipped message keys*, and losing or corrupting those keys makes those
messages permanently undecryptable. The :mod:`doubleratchet.migration_tools` module therefore wraps the
translation in :mod:`doubleratchet.migrations` with operational safeguards. A complete upgrade of a running
service looks like this:

1. **Preflight (read-only).** Call :func:`~doubleratchet.migration_tools.preflight_check` on each parsed
   archive *before* writing anything. It classifies the archive as pre-stable or stable, reports the structure
   (key counts, chain lengths, byte sizes only, never the secrets themselves) and returns fatal ``errors`` plus
   non-fatal ``warnings``.
2. **Refuse what cannot be migrated losslessly.** If ``migratable`` is ``False``, do not touch the file. The
   report tells you whether data is missing, the version is ambiguous, or fields contradict each other.
3. **Migrate on disk with a backup.** :func:`~doubleratchet.migration_tools.migrate_json_file` validates first,
   copies the original byte-for-byte to a ``.bak`` file and writes the stable JSON atomically. On any failure no
   file is created, replaced or deleted, so the original archive stays intact.
4. **Restore and drain the backlog.** Restore both peers with ``DoubleRatchet.from_json`` and decrypt the
   retained, possibly out-of-order messages. Every skipped message key, the sending/receiving chain keys and
   lengths, the root chain and all counters are preserved, so these messages decrypt to their exact original
   plaintexts.
5. **Continue the conversation.** The restored ratchets exchange fresh mutual replies and can be serialized
   again with the stable ``json`` property.

Success criteria
^^^^^^^^^^^^^^^^

A migration is considered successful only when all of the following hold:

* ``preflight_check`` reports no errors for every archive.
* The number of skipped message keys, the distinct skipped ratchet public keys, both chain lengths and the
  previous-sending-chain counter are identical before and after migration.
* Every retained out-of-order message decrypts to its original plaintext on the intended recipient.
* After the backlog is drained, fresh messages travel in both directions across further Diffie-Hellman steps.
* Replaying an already processed message is still rejected (``DuplicateMessageException`` on a live chain, or
  an authentication failure for a one-time skipped key), confirming no key was duplicated or reset.

When a lossless migration is impossible
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The preflight refuses (and the on-disk routine leaves the original file untouched) when, for example:

* The own ratchet **private key** is absent. It cannot be reconstructed, and it is never replaced with a
  randomly generated key.
* The recipient ratchet **public key** is absent, so future/out-of-order messages cannot be addressed.
* The stored own public key **contradicts** the private key (the derived public key differs), a public or
  private key is not a valid X25519/X448 key, or a chain/message key is not valid base64 or has the wrong
  length.
* The archive has an unknown/unsupported ``version``, unexpected top-level fields (an unrecognized
  serializer), or a structurally invalid section.
* The instance is **uninitialized** (no sending chain and no recipient public key yet). Such an instance holds
  no messages and can safely be discarded and re-created with ``encrypt_initial_message`` /
  ``decrypt_initial_message`` instead of migrated.

No secret material is ever generated to fill gaps, and :func:`~doubleratchet.migration_tools.redact_archive`
returns a copy in which private keys, chain keys and skipped message keys are replaced by length-only
placeholders, while public keys, versions and counters remain visible for auditing. A runnable end-to-end
example lives in ``examples/migrate_session.py``.

