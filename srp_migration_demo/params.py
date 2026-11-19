"""Named, immutable SRP parameter sets used by the migration demo.

A record is bound to exactly one parameter set.  The set pins every
interpretation that pysrp leaves to its caller or to process-global state:

* ``hash_alg``  -- the SRP digest (SHA-1 vs. SHA-256, ...)
* ``ng_type``   -- the safe-prime group (here always NG_2048)
* ``x_rule``    -- how the username participates in x = H(s, ...)
* ``rfc5054``   -- whether RFC 5054 width padding is applied inside H()
* ``salt_encoding`` / ``verifier_encoding`` -- on-disk byte representation

pysrp applies ``rfc5054_enable()`` and ``no_username_in_x()`` as module-global
switches, so a process cannot honestly serve two x-derivation rules at once.
The demo therefore fixes the rule globally (pysrp default: username inside x,
non-RFC 5054 hashing) and records that fact explicitly in every record instead
of silently relying on the default.
"""

import srp

# pysrp's gen_x():
#   default           x = H(s, H(username + b':' + password))
#   no_username_in_x  x = H(s, H(b''       + b':' + password))
# rfc5054_enable() additionally changes padding inside H(); it is a global
# toggle as well.  The demo pins both toggles and records the pinned values.
PINNED_X_RULE = "srp_default_username_in_x"  # username participates in x
PINNED_RFC5054 = False

# One registry, one source of truth.  Names are part of the on-disk format;
# never reuse or rename an existing name.
PARAM_SETS = {
    "srp-2048-sha1-pysrp-v1": {
        "name": "srp-2048-sha1-pysrp-v1",
        "hash_alg": srp.SHA1,
        "ng_type": srp.NG_2048,
        "x_rule": PINNED_X_RULE,
        "rfc5054": PINNED_RFC5054,
        "salt_encoding": "hex",
        "verifier_encoding": "hex",
        "salt_len": 16,
    },
    "srp-2048-sha256-pysrp-v1": {
        "name": "srp-2048-sha256-pysrp-v1",
        "hash_alg": srp.SHA256,
        "ng_type": srp.NG_2048,
        "x_rule": PINNED_X_RULE,
        "rfc5054": PINNED_RFC5054,
        "salt_encoding": "hex",
        "verifier_encoding": "hex",
        "salt_len": 16,
    },
}

LEGACY_PARAM_SET = "srp-2048-sha1-pysrp-v1"
TARGET_PARAM_SET = "srp-2048-sha256-pysrp-v1"

# The only in-place upgrade path supported by the demo.
UPGRADE_PATHS = {LEGACY_PARAM_SET: TARGET_PARAM_SET}


class ParameterError(ValueError):
    """Raised when a parameter set is unknown or used inconsistently."""


def get_param_set(name):
    try:
        return PARAM_SETS[name]
    except KeyError:
        raise ParameterError("unknown parameter set: %r" % name)


def assert_globals_pinned():
    """Fail fast if pysrp's global derivation toggles were changed.

    Both client and server call this before touching the network.  The
    x-derivation rule is process-global, so every record in this demo must
    use the pinned rule -- this is what makes the recorded ``x_rule`` field
    a truthful description rather than a hint.
    """
    if srp._mod._rfc5054_compat != PINNED_RFC5054:
        raise ParameterError(
            "rfc5054 global toggle drifted; record metadata would lie")
    if srp._mod._no_username_in_x is not False:
        raise ParameterError(
            "no_username_in_x global toggle drifted; record metadata would lie")


def assert_consistent(record_param_set, requested_param_set):
    """Handshake parameters come from the record, never renegotiated.

    pysrp constructors take hash_alg/ng_type as arguments, so a careless
    server could instantiate the Verifier with different parameters than
    those stored on the record.  That mismatch is exactly what this guard
    refuses: the client must ask for the record's own parameter set and the
    server uses it unchanged for the whole handshake.
    """
    if record_param_set != requested_param_set:
        raise ParameterError(
            "refusing to renegotiate SRP interpretation: record is bound to "
            "%r but %r was requested" % (record_param_set,
                                         requested_param_set))


def describe(name):
    """Stable, serializable description embedded in every record."""
    ps = get_param_set(name)
    return {
        "param_set": ps["name"],
        "group": "NG_2048",
        "digest": {srp.SHA1: "sha1", srp.SHA256: "sha256"}[ps["hash_alg"]],
        "x_rule": ps["x_rule"],
        "rfc5054_padding": ps["rfc5054"],
        "salt_encoding": ps["salt_encoding"],
        "verifier_encoding": ps["verifier_encoding"],
    }
