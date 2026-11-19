"""Provenance and conflict model for ELF external-call identities.

A single call site can be described by more than one producer, and the producers do not say
the same kind of thing:

* a relocation declares which symbol a slot is *supposed* to be bound to, together with the
  symbol version that disambiguates same-named imports (``memcpy@GLIBC_2.2.5`` versus
  ``memcpy@GLIBC_2.14``);
* a PLT stub is code the image contains, naming the slot it branches through;
* a GOT slot is storage, and what it holds at analysis time says whether it is bound yet;
* a heuristic name is what a disassembler guessed from shape alone.

Collapsing those into one ``(dll, name)`` tuple is what lets a display layer pick a name and
present it as confirmed. This module keeps the individual claims, each with its source, and
puts them in a container that records *conflicts* rather than resolving them: two claims only
agree when their full identity (name, version, weak flag) agrees. Callers can ask for a single
display name, which returns None while the claims disagree.

Nothing here loads a shared object or asks a dynamic linker to bind a slot. The state of a GOT
slot is observed from the mapped image and from the relocation entries that exist in the file.
"""

import json
import logging

LOGGER = logging.getLogger(__name__)

# Kinds of evidence, ordered from what the image states to what a disassembler guessed.
RELOCATION = "relocation"
PLT_STUB = "plt_stub"
GOT_SLOT = "got_slot"
SYMBOL_TABLE = "symbol_table"
HEURISTIC = "heuristic"

EVIDENCE_KINDS = frozenset({RELOCATION, PLT_STUB, GOT_SLOT, SYMBOL_TABLE, HEURISTIC})

# How a call instruction reached whatever it called. This is an address-level fact, kept next
# to the name claims so that a consumer can tell "the instruction targeted 0x1030, a PLT stub"
# from "a relocation entry for that slot names memcpy@GLIBC_2.14".
TARGET_DIRECT = "direct"
TARGET_PLT_STUB = "plt_stub"
TARGET_SLOT = "slot"
TARGET_UNKNOWN = "unknown"
TARGET_KINDS = frozenset({TARGET_DIRECT, TARGET_PLT_STUB, TARGET_SLOT, TARGET_UNKNOWN})

# What the call site's identity amounts to. DECLARED is deliberately distinct from CONFIRMED:
# a relocation states what a slot is meant to be bound to, not that this image has bound it.
STATE_CONFIRMED = "confirmed"
STATE_DECLARED = "declared"
STATE_CONFLICTED = "conflicted"
STATE_UNKNOWN = "unknown"
IDENTITY_STATES = frozenset({STATE_CONFIRMED, STATE_DECLARED, STATE_CONFLICTED, STATE_UNKNOWN})

# A slot can be described as bound, unbound, or not observable at all. UNOBSERVED differs from
# UNBOUND: an image whose slot the loader has already filled says nothing about whether the
# binding happened, while a slot holding zero or only its lazy-binding trampoline has not been
# bound to anything yet.
BINDING_BOUND = "bound"
BINDING_LAZY = "lazy"
BINDING_UNBOUND = "unbound"
BINDING_UNOBSERVED = "unobserved"
BINDING_UNKNOWN = "unknown"

BINDING_STATES = frozenset({BINDING_BOUND, BINDING_LAZY, BINDING_UNBOUND, BINDING_UNOBSERVED, BINDING_UNKNOWN})

# States in which a GOT slot still holds no resolved address, so a name read out of it would be
# invented rather than observed.
UNRESOLVED_BINDING_STATES = frozenset({BINDING_LAZY, BINDING_UNBOUND, BINDING_UNOBSERVED, BINDING_UNKNOWN})


def compose_display_name(library, name):
    """The ``dll!api`` string the report has always used, given an import entry.

    On ELF, ``library`` holds the version requirement, so this is the conventional
    ``GLIBC_2.2.5!memcpy`` spelling. It is only ever built from two values that agree; a
    disputed call site must not be rendered through it.
    """
    return "{}!{}".format(library if library is not None else "", name)


def normalize_symbol_version(value):
    """Return a version string, or None when no version is stated.

    An empty string is how an ELF spells "no version" in a symbol version table, so it is
    treated as absent rather than as a version that happens to be named "".
    """
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    return value or None


class ElfCallEvidence:
    """One producer's claim about the identity of an external call target."""

    __slots__ = ("kind", "name", "version", "library", "weak", "slot", "binding", "detail")

    def __init__(
        self,
        kind,
        name,
        version=None,
        library=None,
        weak=None,
        slot=None,
        binding=None,
        detail=None,
    ):
        if kind not in EVIDENCE_KINDS:
            raise ValueError(f"unknown ELF call evidence kind: {kind!r}")
        if not name:
            raise ValueError("ELF call evidence must carry a name")
        self.kind = kind
        self.name = name
        self.version = normalize_symbol_version(version)
        self.library = library or None
        self.weak = weak
        self.slot = slot
        self.binding = binding if binding in BINDING_STATES else None
        self.detail = detail or None

    @property
    def identity(self):
        """The full identity a consumer has to compare: name, version and weak flag.

        Comparing names alone would merge ``memcpy@GLIBC_2.2.5`` with ``memcpy@GLIBC_2.14``,
        which is exactly the merge a caller relying on symbol versions must not make.
        """
        return (self.name, self.version, self.weak)

    def is_resolved(self):
        """Whether this claim names a target the image has actually bound.

        A GOT-slot observation in an unresolved state is information about the slot, not a
        confirmed identity, so it never counts as resolved on its own. An undefined weak
        symbol may legally resolve to zero, so the declaration alone is not a resolution
        either - it stays a declaration (or unknown) until something binds it. A heuristic
        name is a guess by construction and never resolves anything.
        """
        if self.kind == HEURISTIC:
            return False
        if self.kind == GOT_SLOT and self.binding in UNRESOLVED_BINDING_STATES:
            return False
        return not (self.kind in (RELOCATION, SYMBOL_TABLE) and self.weak is True)

    def compatible_with(self, other):
        """Whether two claims can describe the same symbol without contradicting each other.

        Names decide first. Versions decide only when both claims state one: a claim that
        states no version is less specific, not a different symbol, so a bare heuristic name
        does not turn every versioned import into a conflict. Weakness is compared the same
        way, only when both state it.
        """
        if self.name != other.name:
            return False
        if self.version and other.version and self.version != other.version:
            return False
        return not (self.weak is not None and other.weak is not None and self.weak != other.weak)

    def toDict(self):
        return {
            "kind": self.kind,
            "name": self.name,
            "version": self.version,
            "library": self.library,
            "weak": self.weak,
            "slot": self.slot,
            "binding": self.binding,
            "detail": self.detail,
        }

    @classmethod
    def fromDict(cls, evidence_dict):
        if not isinstance(evidence_dict, dict):
            raise ValueError("serialized ELF call evidence must be a dictionary")
        return cls(
            evidence_dict.get("kind"),
            evidence_dict.get("name"),
            version=evidence_dict.get("version"),
            library=evidence_dict.get("library"),
            weak=evidence_dict.get("weak"),
            slot=evidence_dict.get("slot"),
            binding=evidence_dict.get("binding"),
            detail=evidence_dict.get("detail"),
        )

    def _key(self):
        return (
            self.kind,
            self.name,
            self.version,
            self.library,
            self.weak,
            self.slot,
            self.binding,
            self.detail,
        )

    def __eq__(self, other):
        if not isinstance(other, ElfCallEvidence):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self):
        return hash(self._key())

    def __repr__(self):
        return (
            f"ElfCallEvidence(kind={self.kind!r}, name={self.name!r}, version={self.version!r}, "
            f"library={self.library!r}, weak={self.weak!r}, slot={self.slot!r}, binding={self.binding!r})"
        )


def _claim_sort_key(claim):
    return (
        claim.kind,
        claim.name,
        claim.version or "",
        claim.slot if claim.slot is not None else -1,
        claim.detail or "",
    )


def _serialize_evidence(claims):
    """Deterministic order: a report written twice from the same analysis is byte-identical."""
    return [claim.toDict() for claim in sorted(claims, key=_claim_sort_key)]


def _deserialize_evidence(entries):
    if entries is None:
        return []
    if not isinstance(entries, list):
        raise ValueError("serialized ELF call evidence list must be a list")
    return [ElfCallEvidence.fromDict(entry) for entry in entries]


class ElfCallSiteEvidence:
    """Every claim made about one call instruction, with their disagreements kept.

    The container is the report's record that identity is disputed. ``display_name()`` returns
    None while claims disagree so that no consumer can mistake a pick for a confirmation, and
    ``conflict_groups()`` states which identities are in play.
    """

    __slots__ = ("call_addr", "target_addr", "slot", "claims", "target_kind", "binding")

    def __init__(
        self,
        call_addr,
        target_addr=None,
        slot=None,
        claims=None,
        target_kind=None,
        binding=None,
    ):
        self.call_addr = call_addr
        self.target_addr = target_addr
        self.slot = slot
        self.target_kind = target_kind if target_kind in TARGET_KINDS else TARGET_UNKNOWN
        self.binding = binding if binding in BINDING_STATES else None
        self.claims = []
        for claim in claims or ():
            self.add(claim)

    def add(self, claim):
        if not isinstance(claim, ElfCallEvidence):
            raise ValueError("a call site only holds ElfCallEvidence instances")
        if claim not in self.claims:
            self.claims.append(claim)

    def extend(self, claims):
        for claim in claims:
            self.add(claim)

    def identities(self):
        """Distinct full identities among the claims, in first-seen order."""
        seen = []
        for claim in self.claims:
            if claim.identity not in seen:
                seen.append(claim.identity)
        return seen

    def has_conflict(self):
        """Whether the claims assert symbols that cannot all be the same one.

        Every pair is compared; two versioned claims for different versions of one base
        name conflict even though their names agree. A claim without a version is treated
        as less specific rather than as a contradiction (see ``compatible_with``).
        """
        claims = self.claims
        for index, claim in enumerate(claims):
            for other in claims[index + 1 :]:
                if not claim.compatible_with(other):
                    return True
        return False

    def identity_state(self):
        """Classify what is known about this call's identity.

        * ``unknown``     - nothing names it, or every claim is weak/unresolved.
        * ``declared``    - one identity is stated by the image, but nothing shows it bound.
        * ``confirmed``   - one identity is stated and a binding observation agrees.
        * ``conflicted``  - the claims assert different identities; no pick is made.
        """
        if not self.claims:
            return STATE_UNKNOWN
        if self.has_conflict():
            return STATE_CONFLICTED
        resolved = [claim for claim in self.claims if claim.is_resolved()]
        if not resolved:
            return STATE_UNKNOWN
        declarations = [claim for claim in self.claims if claim.kind in (RELOCATION, SYMBOL_TABLE)]
        if not declarations:
            # a PLT-stub spelling or a heuristic name without a declaration names a function
            # but not a dynamic-symbol identity, so it never rises above unknown here
            return STATE_UNKNOWN
        if self.binding == BINDING_BOUND:
            # the slot's contents agree with the declaration, which is as close to a
            # confirmed call as an image that is never loaded can get
            return STATE_CONFIRMED
        if self.binding in (BINDING_UNBOUND, BINDING_LAZY):
            # the relocation states an identity, but the slot still holds no bound address:
            # declaration only, never confirmation
            return STATE_DECLARED
        return STATE_DECLARED

    def is_confirmed(self):
        """Whether the claims agree and a binding observation backs the identity."""
        return self.identity_state() == STATE_CONFIRMED

    def is_declared(self):
        return self.identity_state() == STATE_DECLARED

    def is_unknown(self):
        return self.identity_state() in (STATE_UNKNOWN, STATE_CONFLICTED)

    def display_name(self):
        """The one name to show, or None while the claims disagree or resolve to nothing.

        A declaration is shown as a declaration (``identity_state() == "declared"``), never
        as a confirmed call; a conflict or an unresolved slot yields None rather than a pick.
        """
        state = self.identity_state()
        if state in (STATE_CONFLICTED, STATE_UNKNOWN):
            return None
        resolved = [claim for claim in self.claims if claim.is_resolved()]
        if not resolved:
            return None
        resolved.sort(key=lambda claim: claim.version is not None, reverse=True)
        return _spell(resolved[0])

    def conflict_groups(self):
        """Map each disputed identity to the claim kinds that assert it."""
        if not self.has_conflict():
            return {}
        groups = {}
        for claim in self.claims:
            groups.setdefault(claim.identity, []).append(claim.kind)
        return {identity: sorted(set(kinds)) for identity, kinds in groups.items()}

    def evidence_kinds(self):
        return sorted({claim.kind for claim in self.claims})

    def conflict_identities(self):
        """The disputed identities, each spelled the way a consumer would display it."""
        identities = []
        for identity, kinds in self.conflict_groups().items():
            name, version, weak = identity
            identities.append({"name": name, "version": version, "weak": weak, "evidence_kinds": kinds})
        return sorted(identities, key=lambda entry: (entry["name"], entry["version"] or "", bool(entry["weak"])))

    def toDict(self):
        return {
            "call_addr": self.call_addr,
            "target_addr": self.target_addr,
            "slot": self.slot,
            "target_kind": self.target_kind,
            "binding": self.binding,
            "identity_state": self.identity_state(),
            "evidence_kinds": self.evidence_kinds(),
            "conflict": self.has_conflict(),
            "conflicting_identities": self.conflict_identities(),
            # a name is only present when the claims agree; it is never a pick among them
            "resolved_name": self.display_name(),
            "claims": _serialize_evidence(self.claims),
        }

    @classmethod
    def fromDict(cls, evidence_dict):
        if not isinstance(evidence_dict, dict):
            raise ValueError("serialized ELF call-site evidence must be a dictionary")
        call_addr = evidence_dict.get("call_addr")
        if not isinstance(call_addr, int) or isinstance(call_addr, bool):
            raise ValueError("serialized ELF call-site evidence must name an integer call address")
        return cls(
            call_addr,
            target_addr=evidence_dict.get("target_addr"),
            slot=evidence_dict.get("slot"),
            claims=_deserialize_evidence(evidence_dict.get("claims")),
            target_kind=evidence_dict.get("target_kind"),
            binding=evidence_dict.get("binding"),
        )


def _spell(claim):
    """Render one claim as the conventional ``name@version`` display string."""
    name = claim.name
    if claim.version:
        name = f"{name}@{claim.version}"
    if claim.library and claim.library != claim.version:
        return f"{claim.library}!{name}"
    return name


class ElfCallEvidenceTable:
    """Call sites by instruction address, serialized as JSON-safe data beside the report.

    Address keys are stringified in ``toDict`` because JSON object keys are strings; the
    decoder restores them to ints so the model matches what the analysis produced.
    """

    __slots__ = ("sites",)

    def __init__(self, sites=None):
        self.sites = {}
        for site in sites or ():
            self.add(site)

    def add(self, site):
        if not isinstance(site, ElfCallSiteEvidence):
            raise ValueError("an evidence table only holds ElfCallSiteEvidence instances")
        existing = self.sites.get(site.call_addr)
        if existing is None:
            self.sites[site.call_addr] = site
            return site
        existing.extend(site.claims)
        if existing.target_addr is None:
            existing.target_addr = site.target_addr
        if existing.slot is None:
            existing.slot = site.slot
        if site.target_kind != TARGET_UNKNOWN:
            existing.target_kind = site.target_kind
        if site.binding is not None and site.binding != BINDING_UNOBSERVED:
            existing.binding = site.binding
        return existing

    def get(self, call_addr):
        return self.sites.get(call_addr)

    def record(
        self,
        call_addr,
        claim,
        target_addr=None,
        slot=None,
        target_kind=None,
        binding=None,
    ):
        """Add one claim to a call site, creating it when this is the first claim."""
        site = self.sites.get(call_addr)
        if site is None:
            site = ElfCallSiteEvidence(
                call_addr,
                target_addr=target_addr,
                slot=slot,
                target_kind=target_kind,
                binding=binding,
            )
            self.sites[call_addr] = site
        else:
            if target_addr is not None:
                site.target_addr = target_addr
            if slot is not None:
                site.slot = slot
            if target_kind is not None:
                site.target_kind = target_kind
            if binding is not None:
                site.binding = binding
        site.add(claim)
        return site

    def conflicts(self):
        return {addr: site for addr, site in self.sites.items() if site.has_conflict()}

    def confirmed(self):
        return {addr: site for addr, site in self.sites.items() if site.is_confirmed()}

    def toDict(self):
        return {str(call_addr): self.sites[call_addr].toDict() for call_addr in sorted(self.sites)}

    @classmethod
    def fromDict(cls, table_dict):
        if table_dict is None:
            return cls()
        if not isinstance(table_dict, dict):
            raise ValueError("serialized ELF call evidence table must be a dictionary")
        table = cls()
        for call_addr, entry in table_dict.items():
            if isinstance(call_addr, bool):
                raise ValueError("serialized ELF call evidence keys must be addresses")
            try:
                address = int(call_addr)
            except (TypeError, ValueError) as exc:
                raise ValueError("serialized ELF call evidence keys must be addresses") from exc
            site = ElfCallSiteEvidence.fromDict(entry)
            if site.call_addr != address:
                raise ValueError("serialized ELF call evidence call address must match its key")
            table.add(site)
        return table

    def __len__(self):
        return len(self.sites)

    def __iter__(self):
        return iter(self.sites.values())


def claims_to_json(claims):
    """JSON-safe rendering of a claim list, for callers that embed it in another document."""
    return json.dumps(_serialize_evidence(claims), sort_keys=True)
