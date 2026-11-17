#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Tag Misalignment Mutation Tests
-------------------------------

Bounded mutation testing of nested opening/closing context tags in
WriteProperty and COV notification service requests.  The goal is to prove
that a mis-tagged, mis-nested, mis-lengthed, or unterminated value cannot
escape its field and be attributed to another (security-relevant) field such
as the object identifier, the property identifier, or a sibling property
value in a COV notification.

Methodology:

- Valid seed messages are encoded once with the real encoders; an
  independent field layout (oracle) is kept separately in this file.
- Mutations only change tag numbers, nesting (opening/closing tags), tag
  lengths (LVT), and may drop closing tags.  The APCI header is never
  touched.
- Each mutant is classified by the independent oracle: structurally legal
  (including legal unknown/trailing optional tags) or corrupt (required
  field damaged, unbalanced nesting, bad length).
- Mutants are run through the real APDU decode path (``APDU.decode`` +
  ``APCISequence.decode``) and the real service dispatch
  (``Application.indication``), recording the object/property/value
  attribution of every accepted request.
- An exception is never counted as a vulnerability by itself: corrupt
  variants are *expected* to be rejected.  Findings are: a corrupt variant
  being accepted, an accepted variant whose recorded attribution differs
  from the independent expectation, or a rejected variant that still
  produced a write/notification side effect.
- The seeded fuzzer saves minimal byte counterexamples (and the seed) for
  every finding.
"""

import json
import os
import random
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, Dict, List, NamedTuple, Optional, Tuple

import pytest

from bacpypes3.pdu import PDU, Address
from bacpypes3.primitivedata import (
    Tag,
    TagClass,
    TagNumber,
    TagList,
    OpeningTag,
    ClosingTag,
    Unsigned,
    Integer,
    Real,
    Null,
    ObjectIdentifier,
    PropertyIdentifier,
)
from bacpypes3.constructeddata import Any
from bacpypes3.basetypes import PropertyValue, StatusFlags
from bacpypes3.apdu import (
    APDU,
    APCISequence,
    SimpleAckPDU,
    WritePropertyRequest,
    ConfirmedCOVNotificationRequest,
    UnconfirmedCOVNotificationRequest,
)
from bacpypes3.app import Application
from bacpypes3.local.analog import AnalogValueObjectCmd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SOURCE_ADDRESS = Address("1.2.3.4")
INVOKE_ID = 42
SUBSCRIBER_PROCESS_ID = 7

FINDINGS_DIR = Path(
    os.environ.get(
        "TAG_MISALIGNMENT_FINDINGS_DIR",
        Path(__file__).resolve().parent / "tag_misalignment_findings",
    )
)
FUZZ_SEED = int(os.environ.get("TAG_MISALIGNMENT_SEED", "47806"), 0)  # 0xBABE
FUZZ_ITERATIONS = int(os.environ.get("TAG_MISALIGNMENT_ITERATIONS", "300"), 0)


# ---------------------------------------------------------------------------
# Independent tag tokenizer (mirrors Tag.decode byte-for-byte)
# ---------------------------------------------------------------------------


class OracleReject(Exception):
    """The independent oracle considers the byte stream structurally corrupt."""


@dataclass
class Tok:
    cls: TagClass
    num: int
    lvt: int
    data: bytes
    start: int
    end: int


def tokenize(payload: bytes) -> List[Tok]:
    """Split a payload into tags exactly the way Tag.decode would."""
    toks: List[Tok] = []
    pos, end = 0, len(payload)
    while pos < end:
        start = pos
        initial = payload[pos]
        pos += 1

        cls = TagClass((initial >> 3) & 0x01)

        num = initial >> 4
        if num == 0x0F:
            if pos >= end:
                raise OracleReject("truncated extended tag number")
            num = payload[pos]
            pos += 1

        lvt = initial & 0x07
        if lvt == 5:
            if pos >= end:
                raise OracleReject("truncated extended length")
            lvt = payload[pos]
            pos += 1
            if lvt == 254:
                if pos + 2 > end:
                    raise OracleReject("truncated extended length")
                lvt = struct.unpack(">H", payload[pos : pos + 2])[0]
                pos += 2
            elif lvt == 255:
                if pos + 4 > end:
                    raise OracleReject("truncated extended length")
                lvt = struct.unpack(">I", payload[pos : pos + 4])[0]
                pos += 4
        elif lvt == 6:
            cls = TagClass.opening
            lvt = 0
        elif lvt == 7:
            cls = TagClass.closing
            lvt = 0

        if (cls == TagClass.application) and (num == TagNumber.boolean):
            data = b""
        else:
            if pos + lvt > end:
                raise OracleReject("truncated tag data")
            data = payload[pos : pos + lvt]
            pos += lvt

        toks.append(Tok(cls, num, lvt, data, start, pos))
    return toks


# ---------------------------------------------------------------------------
# Mutations: tag numbers, nesting, lengths, missing closing tags
# ---------------------------------------------------------------------------


class Mutation:
    def apply(self, payload: bytes) -> bytes:
        raise NotImplementedError

    def describe(self) -> str:
        raise NotImplementedError


@dataclass
class Retag(Mutation):
    """Rewrite the tag number of the token at index."""

    index: int
    new_number: int

    def apply(self, payload: bytes) -> bytes:
        toks = tokenize(payload)
        tok = toks[self.index]
        if not 0 <= self.new_number < 15:
            raise ValueError("retag target out of range")
        first = payload[tok.start]
        return (
            payload[: tok.start]
            + bytes([(self.new_number << 4) | (first & 0x0F)])
            + payload[tok.start + 1 :]
        )

    def describe(self) -> str:
        return f"Retag(index={self.index}, number={self.new_number})"


@dataclass
class SetLvt(Mutation):
    """Rewrite the length/value/type bits of the token at index."""

    index: int
    new_lvt: int

    def apply(self, payload: bytes) -> bytes:
        toks = tokenize(payload)
        tok = toks[self.index]
        if not 0 <= self.new_lvt < 8:
            raise ValueError("lvt out of range")
        first = payload[tok.start]
        return (
            payload[: tok.start]
            + bytes([(first & 0xF8) | self.new_lvt])
            + payload[tok.start + 1 :]
        )

    def describe(self) -> str:
        return f"SetLvt(index={self.index}, lvt={self.new_lvt})"


@dataclass
class Drop(Mutation):
    """Remove the token at index (e.g. a closing tag)."""

    index: int

    def apply(self, payload: bytes) -> bytes:
        toks = tokenize(payload)
        tok = toks[self.index]
        return payload[: tok.start] + payload[tok.end :]

    def describe(self) -> str:
        return f"Drop(index={self.index})"


@dataclass
class Insert(Mutation):
    """Insert raw bytes at a token boundary."""

    index: int
    raw: bytes

    def apply(self, payload: bytes) -> bytes:
        toks = tokenize(payload)
        offset = toks[self.index].start if self.index < len(toks) else len(payload)
        return payload[:offset] + self.raw + payload[offset:]

    def describe(self) -> str:
        return f"Insert(index={self.index}, raw={self.raw.hex()})"


def apply_mutations(payload: bytes, mutations: List[Mutation]) -> bytes:
    for mutation in mutations:
        payload = mutation.apply(payload)
    return payload


# ---------------------------------------------------------------------------
# Independent field layouts (the oracle)
# ---------------------------------------------------------------------------


class F(NamedTuple):
    name: str
    ctx: int
    kind: str  # 'uint', 'int', 'objid', 'propid', 'any', 'seq'
    required: bool
    sub: Tuple["F", ...] = ()


WRITE_PROPERTY_LAYOUT = (
    F("objectIdentifier", 0, "objid", True),
    F("propertyIdentifier", 1, "propid", True),
    F("propertyArrayIndex", 2, "uint", False),
    F("propertyValue", 3, "any", True),
    F("priority", 4, "int", False),
)

PROPERTY_VALUE_LAYOUT = (
    F("propertyIdentifier", 0, "propid", True),
    F("propertyArrayIndex", 1, "uint", False),
    F("value", 2, "any", True),
    F("priority", 3, "uint", False),
)

COV_LAYOUT = (
    F("subscriberProcessIdentifier", 0, "uint", True),
    F("initiatingDeviceIdentifier", 1, "objid", True),
    F("monitoredObjectIdentifier", 2, "objid", True),
    F("timeRemaining", 3, "uint", True),
    F("listOfValues", 4, "seq", True, PROPERTY_VALUE_LAYOUT),
)

ABSENT = object()
UNINTERPRETABLE = object()

_ATOMIC_DECODERS = {
    "uint": (TagNumber.unsigned, Unsigned),
    "int": (TagNumber.integer, Integer),
    "objid": (TagNumber.objectIdentifier, ObjectIdentifier),
    "propid": (TagNumber.enumerated, PropertyIdentifier),
}


class AnyValue(NamedTuple):
    raw: bytes
    inner: List[Tok]


def _tok_to_tag(tok: Tok) -> Tag:
    if tok.cls == TagClass.opening:
        return OpeningTag(tok.num)
    if tok.cls == TagClass.closing:
        return ClosingTag(tok.num)
    return Tag(tok.cls, tok.num, tok.lvt, tok.data)


def _decode_atomic(kind: str, tok: Tok):
    app_number, element_class = _ATOMIC_DECODERS[kind]
    tag = Tag(TagClass.context, tok.num, tok.lvt, tok.data)
    app_tag = tag.context_to_app(app_number)
    return element_class.decode(TagList([app_tag]))


def _consume_any(toks: List[Tok], pos: int, field_: F) -> Tuple[AnyValue, int]:
    opening = toks[pos]
    if opening.cls == TagClass.context:
        # a context-tagged ANY may legally be a single primitive context tag
        # without opening/closing tags (BACnet 20.2.13)
        raw = bytes(TagList([_tok_to_tag(opening)]).encode().pduData)
        return AnyValue(raw=raw, inner=[opening]), pos + 1
    if opening.cls != TagClass.opening:
        raise OracleReject(f"opening tag {field_.ctx} expected for {field_.name}")
    lvl = 0
    matched: Optional[int] = None
    i = pos + 1
    while i < len(toks):
        tok = toks[i]
        if tok.cls == TagClass.opening:
            lvl += 1
        elif tok.cls == TagClass.closing:
            if lvl == 0:
                if tok.num != opening.num:
                    raise OracleReject(f"mismatched closing tag for {field_.name}")
                matched = i
                break
            lvl -= 1
        i += 1
    if matched is None:
        raise OracleReject(f"missing closing tag for {field_.name}")
    raw = bytes(
        TagList([_tok_to_tag(t) for t in toks[pos : matched + 1]]).encode().pduData
    )
    return AnyValue(raw=raw, inner=toks[pos + 1 : matched]), matched + 1


def _consume_seq(toks: List[Tok], pos: int, field_: F) -> Tuple[list, int]:
    opening = toks[pos]
    if opening.cls != TagClass.opening:
        raise OracleReject(f"opening tag {field_.ctx} expected for {field_.name}")
    pos += 1
    items = []
    while True:
        if pos >= len(toks):
            raise OracleReject(f"missing closing tag {field_.ctx} for {field_.name}")
        if toks[pos].cls == TagClass.closing:
            if toks[pos].num != field_.ctx:
                raise OracleReject(f"mismatched closing tag for {field_.name}")
            pos += 1
            break
        item, pos = oracle_walk(toks, pos, field_.sub)
        items.append(item)
    return items, pos


def oracle_walk(toks: List[Tok], pos: int, layout: Tuple[F, ...]) -> Tuple[dict, int]:
    attr: Dict[str, object] = {}
    for field_ in layout:
        if pos >= len(toks) or toks[pos].cls == TagClass.closing:
            if field_.required:
                raise OracleReject(f"missing required {field_.name}")
            attr[field_.name] = ABSENT
            continue
        tok = toks[pos]
        if tok.cls in (TagClass.context, TagClass.opening) and tok.num == field_.ctx:
            if field_.kind == "any":
                value, pos = _consume_any(toks, pos, field_)
            elif field_.kind == "seq":
                value, pos = _consume_seq(toks, pos, field_)
            else:
                if tok.cls != TagClass.context:
                    raise OracleReject(f"opening tag not allowed for {field_.name}")
                try:
                    value = _decode_atomic(field_.kind, tok)
                except Exception as err:
                    raise OracleReject(f"cannot decode {field_.name}: {err}")
                pos += 1
            attr[field_.name] = value
        else:
            if field_.required:
                raise OracleReject(f"tag mismatch for required {field_.name}")
            attr[field_.name] = ABSENT
    return attr, pos


def run_oracle(layout: Tuple[F, ...], payload: bytes) -> dict:
    """Attribute the payload fields per the independent layout.

    Trailing tags after the last known field are legal unknown optionals and
    are ignored; anything corrupting a required field raises OracleReject.
    """
    toks = tokenize(payload)
    attr, _ = oracle_walk(toks, 0, layout)
    return attr


def _decode_any_inner(any_value: AnyValue):
    """Decode a single application-tagged inner value, if there is one."""
    inner = any_value.inner
    if len(inner) != 1 or inner[0].cls != TagClass.application:
        return UNINTERPRETABLE
    try:
        obj = _tok_to_tag(inner[0]).app_to_object()
    except Exception:
        return UNINTERPRETABLE
    if obj is None:
        return UNINTERPRETABLE
    if isinstance(obj, Null):
        return None
    return obj


def _opt_int(value) -> Optional[int]:
    if value is ABSENT or value is None:
        return None
    return int(value)


def _norm_value(value):
    if isinstance(value, Null):
        return None
    if isinstance(value, float):
        return float(value)
    return value


def expected_write_attribution(attr: dict) -> tuple:
    value = _decode_any_inner(attr["propertyValue"])
    if value is not UNINTERPRETABLE:
        value = _norm_value(value)
    return (
        str(attr["objectIdentifier"]),
        str(attr["propertyIdentifier"]),
        _opt_int(attr["propertyArrayIndex"]),
        value,
        _opt_int(attr["priority"]),
    )


def expected_cov_attribution(attr: dict) -> tuple:
    return (
        int(attr["subscriberProcessIdentifier"]),
        str(attr["initiatingDeviceIdentifier"]),
        str(attr["monitoredObjectIdentifier"]),
        int(attr["timeRemaining"]),
        [
            (
                str(item["propertyIdentifier"]),
                _opt_int(item["propertyArrayIndex"]),
                item["value"].raw.hex(),
                _opt_int(item["priority"]),
            )
            for item in attr["listOfValues"]
        ],
    )


# ---------------------------------------------------------------------------
# Seed messages
# ---------------------------------------------------------------------------


@dataclass
class MessageSpec:
    name: str
    service: str  # 'writeProperty', 'unconfirmedCOV', 'confirmedCOV'
    header: bytes
    payload: bytes
    layout: Tuple[F, ...]


def _write_property_payload(with_priority: bool) -> bytes:
    request = WritePropertyRequest(
        objectIdentifier=ObjectIdentifier("analogValue,1"),
        propertyIdentifier="presentValue",
        propertyValue=Any(Real(72.5)),
        priority=Integer(8) if with_priority else None,
    )
    return bytes(request.encode().pduData)


def _cov_payload(request_class) -> bytes:
    request = request_class(
        subscriberProcessIdentifier=SUBSCRIBER_PROCESS_ID,
        initiatingDeviceIdentifier=ObjectIdentifier("device,99"),
        monitoredObjectIdentifier=ObjectIdentifier("analogValue,1"),
        timeRemaining=60,
        listOfValues=[
            PropertyValue(propertyIdentifier="presentValue", value=Any(Real(72.5))),
            PropertyValue(
                propertyIdentifier="statusFlags", value=Any(StatusFlags([0, 0, 0, 0]))
            ),
        ],
    )
    return bytes(request.encode().pduData)


CONFIRMED_HEADER_WP = bytes([0x00, 0x05, INVOKE_ID, 15])
CONFIRMED_HEADER_CCOV = bytes([0x00, 0x05, INVOKE_ID, 1])
UNCONFIRMED_HEADER_UCOV = bytes([0x10, 0x02])

MESSAGE_SPECS: Dict[str, MessageSpec] = {
    "wp-simple": MessageSpec(
        "wp-simple",
        "writeProperty",
        CONFIRMED_HEADER_WP,
        _write_property_payload(False),
        WRITE_PROPERTY_LAYOUT,
    ),
    "wp-priority": MessageSpec(
        "wp-priority",
        "writeProperty",
        CONFIRMED_HEADER_WP,
        _write_property_payload(True),
        WRITE_PROPERTY_LAYOUT,
    ),
    "ucov": MessageSpec(
        "ucov",
        "unconfirmedCOV",
        UNCONFIRMED_HEADER_UCOV,
        _cov_payload(UnconfirmedCOVNotificationRequest),
        COV_LAYOUT,
    ),
    "ccov": MessageSpec(
        "ccov",
        "confirmedCOV",
        CONFIRMED_HEADER_CCOV,
        _cov_payload(ConfirmedCOVNotificationRequest),
        COV_LAYOUT,
    ),
}

# ---------------------------------------------------------------------------
# System under test: real APDU decode + real service dispatch
# ---------------------------------------------------------------------------


class _WriteRecorder(AnalogValueObjectCmd):
    writes: ClassVar[list] = []

    async def write_property(self, attr, value, index=None, priority=None):
        type(self).writes.append(
            (
                str(self.objectIdentifier),
                str(attr),
                int(index) if index is not None else None,
                _norm_value(value),
                int(priority) if priority is not None else None,
            )
        )
        await super().write_property(attr, value, index, priority)


class _COVContextRecorder:
    def __init__(self, monitored_object_identifier):
        self.monitored_object_identifier = monitored_object_identifier
        self.received: List[PropertyValue] = []

    async def put(self, property_value):
        self.received.append(property_value)


class TagMisalignmentApplication(Application):
    def __init__(self):
        super().__init__()
        self.responses: list = []
        self.cov_dispatch: list = []

    async def response(self, apdu):
        self.responses.append(apdu)

    async def indication(self, apdu):
        if isinstance(
            apdu, (ConfirmedCOVNotificationRequest, UnconfirmedCOVNotificationRequest)
        ):
            self.cov_dispatch.append(apdu)
        await super().indication(apdu)


@dataclass
class SUTResult:
    stage: str
    error: Optional[str]
    crashed: bool
    accepted: bool
    ack: bool
    write_attribution: Optional[tuple]
    write_count: int
    cov_attribution: Optional[tuple]
    cov_value_count: int

    @property
    def side_effect(self) -> bool:
        return self.ack or self.write_count > 0 or self.cov_value_count > 0


async def run_sut(spec: MessageSpec, payload: bytes) -> SUTResult:
    """Decode and dispatch one wire message through the real stack."""
    _WriteRecorder.writes = []
    app = TagMisalignmentApplication()
    app.add_object(
        _WriteRecorder(
            objectIdentifier=("analogValue", 1),
            objectName="av1",
            presentValue=0.0,
            statusFlags=[0, 0, 0, 0],
        )
    )
    scm = _COVContextRecorder(ObjectIdentifier("analogValue,1"))
    app._cov_contexts[(SOURCE_ADDRESS, SUBSCRIBER_PROCESS_ID)] = scm

    pdu = PDU(bytearray(spec.header + payload))
    pdu.pduSource = SOURCE_ADDRESS

    try:
        apdu = APDU.decode(pdu)
    except Exception as err:
        return SUTResult(
            "apdu-decode", repr(err), False, False, False, None, 0, None, 0
        )

    try:
        request = APCISequence.decode(apdu)
    except Exception as err:
        return SUTResult(
            "sequence-decode", repr(err), False, False, False, None, 0, None, 0
        )

    try:
        await app.indication(request)
    except Exception as err:
        return SUTResult("dispatch", repr(err), True, False, False, None, 0, None, 0)

    ack = any(isinstance(response, SimpleAckPDU) for response in app.responses)
    writes = list(_WriteRecorder.writes)

    cov_attribution = None
    if app.cov_dispatch:
        cov_apdu = app.cov_dispatch[0]
        cov_attribution = (
            int(cov_apdu.subscriberProcessIdentifier),
            str(cov_apdu.initiatingDeviceIdentifier),
            str(cov_apdu.monitoredObjectIdentifier),
            int(cov_apdu.timeRemaining),
            [
                (
                    str(pv.propertyIdentifier),
                    int(pv.propertyArrayIndex)
                    if pv.propertyArrayIndex is not None
                    else None,
                    bytes(pv.value.encode().encode().pduData).hex(),
                    int(pv.priority) if pv.priority is not None else None,
                )
                for pv in scm.received
            ],
        )

    if spec.service == "writeProperty":
        accepted = ack
    elif spec.service == "unconfirmedCOV":
        accepted = bool(scm.received)
    else:
        accepted = ack and bool(scm.received)

    return SUTResult(
        "dispatch",
        None,
        False,
        accepted,
        ack,
        writes[0] if writes else None,
        len(writes),
        cov_attribution,
        len(scm.received),
    )


# ---------------------------------------------------------------------------
# Finding evaluation
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    kind: str
    detail: str
    spec_name: str
    mutations: List[Mutation] = field(default_factory=list)
    oracle: str = ""
    sut: str = ""


def _attribution_mismatch(
    spec: MessageSpec, oracle_attr: dict, sut: SUTResult
) -> Optional[str]:
    if spec.service == "writeProperty":
        expected = expected_write_attribution(oracle_attr)
        if sut.write_attribution is None:
            return f"accepted with no recorded write, expected {expected!r}"
        if sut.write_count != 1:
            return f"accepted with {sut.write_count} writes, expected 1"
        if UNINTERPRETABLE in expected:
            return f"accepted but oracle cannot interpret value bytes: {expected!r}"
        if sut.write_attribution != expected:
            return f"recorded {sut.write_attribution!r} != expected {expected!r}"
    else:
        expected = expected_cov_attribution(oracle_attr)
        if sut.cov_attribution is None:
            return f"accepted with no recorded notification, expected {expected!r}"
        if sut.cov_attribution != expected:
            return f"recorded {sut.cov_attribution!r} != expected {expected!r}"
    return None


async def evaluate(
    spec: MessageSpec, payload: bytes
) -> Tuple[Optional[Finding], str, SUTResult]:
    """Compare the independent oracle verdict with the real stack behavior."""
    try:
        oracle_attr = run_oracle(spec.layout, payload)
        oracle_verdict = f"accept {oracle_attr!r}"
    except OracleReject as err:
        oracle_attr = None
        oracle_verdict = f"reject ({err})"

    sut = await run_sut(spec, payload)
    sut_summary = (
        f"stage={sut.stage} accepted={sut.accepted} ack={sut.ack} "
        f"writes={sut.write_count} cov_values={sut.cov_value_count} error={sut.error}"
    )

    if sut.crashed:
        return (
            Finding(
                "unhandled-exception",
                f"dispatch crashed: {sut.error}",
                spec.name,
                oracle=oracle_verdict,
                sut=sut_summary,
            ),
            oracle_verdict,
            sut,
        )

    if oracle_attr is None:
        if sut.accepted:
            return (
                Finding(
                    "corrupt-accepted",
                    f"oracle rejected ({oracle_verdict}) but the stack accepted",
                    spec.name,
                    oracle=oracle_verdict,
                    sut=sut_summary,
                ),
                oracle_verdict,
                sut,
            )
    elif sut.accepted:
        mismatch = _attribution_mismatch(spec, oracle_attr, sut)
        if mismatch:
            return (
                Finding(
                    "attribution-mismatch",
                    mismatch,
                    spec.name,
                    oracle=oracle_verdict,
                    sut=sut_summary,
                ),
                oracle_verdict,
                sut,
            )

    if not sut.accepted and sut.side_effect:
        return (
            Finding(
                "reject-with-side-effect",
                "rejected variant still produced a write/ack/notification",
                spec.name,
                oracle=oracle_verdict,
                sut=sut_summary,
            ),
            oracle_verdict,
            sut,
        )

    return None, oracle_verdict, sut


# ---------------------------------------------------------------------------
# Deterministic cases
# ---------------------------------------------------------------------------

WP_BASE_ATTR = ("analog-value,1", "present-value", None, 72.5, None)
WP_PRIO_ATTR = ("analog-value,1", "present-value", None, 72.5, 8)
COV_BASE_ATTR = (
    SUBSCRIBER_PROCESS_ID,
    "device,99",
    "analog-value,1",
    60,
    [
        ("present-value", None, "2e44429100002f", None),
        ("status-flags", None, "2e8204002f", None),
    ],
)

UNKNOWN_CONTEXT_9 = bytes([0x99, 0x00])
CLOSING_9 = bytes([0x9F])
OPENING_5 = bytes([0x5E])
CLOSING_5 = bytes([0x5F])

# expectation: ("accept", attribution) | ("reject",) | ("service-reject",)
DETERMINISTIC_CASES = [
    # --- WriteProperty, no optional fields ---
    ("wp-baseline", "wp-simple", [], ("accept", WP_BASE_ATTR)),
    (
        "wp-unknown-trailing-context",
        "wp-simple",
        [Insert(5, UNKNOWN_CONTEXT_9)],
        ("accept", WP_BASE_ATTR),
    ),
    (
        "wp-unknown-trailing-closing",
        "wp-simple",
        [Insert(5, CLOSING_9)],
        ("accept", WP_BASE_ATTR),
    ),
    ("wp-objid-retagged", "wp-simple", [Retag(0, 5)], ("reject",)),
    ("wp-objid-retagged-onto-propid", "wp-simple", [Retag(0, 1)], ("reject",)),
    ("wp-propid-retagged", "wp-simple", [Retag(1, 9)], ("reject",)),
    ("wp-value-opening-retagged", "wp-simple", [Retag(2, 1)], ("reject",)),
    ("wp-value-opening-retagged-to-objid", "wp-simple", [Retag(2, 0)], ("reject",)),
    ("wp-value-opening-dropped", "wp-simple", [Drop(2)], ("reject",)),
    ("wp-value-closing-dropped", "wp-simple", [Drop(4)], ("reject",)),
    ("wp-value-closing-retagged", "wp-simple", [Retag(4, 4)], ("reject",)),
    ("wp-objid-length-truncated", "wp-simple", [SetLvt(0, 3)], ("reject",)),
    ("wp-objid-length-extended", "wp-simple", [SetLvt(0, 5)], ("reject",)),
    ("wp-real-length-extended", "wp-simple", [SetLvt(3, 5)], ("reject",)),
    ("wp-real-length-truncated", "wp-simple", [SetLvt(3, 3)], ("service-reject",)),
    ("wp-real-becomes-opening", "wp-simple", [SetLvt(3, 6)], ("reject",)),
    (
        "wp-value-extra-nesting",
        "wp-simple",
        [Insert(3, OPENING_5), Insert(5, CLOSING_5)],
        ("service-reject",),
    ),
    # --- WriteProperty with priority ---
    ("wp-prio-baseline", "wp-priority", [], ("accept", WP_PRIO_ATTR)),
    ("wp-prio-dropped", "wp-priority", [Drop(5)], ("accept", WP_BASE_ATTR)),
    (
        "wp-prio-retagged-to-arrayindex",
        "wp-priority",
        [Retag(5, 2)],
        ("accept", WP_BASE_ATTR),
    ),
    (
        "wp-prio-retagged-to-unknown",
        "wp-priority",
        [Retag(5, 9)],
        ("accept", WP_BASE_ATTR),
    ),
    ("wp-prio-value-closing-dropped", "wp-priority", [Drop(4)], ("reject",)),
    ("wp-prio-value-closing-retagged", "wp-priority", [Retag(4, 4)], ("reject",)),
    # --- Unconfirmed COV notification ---
    ("ucov-baseline", "ucov", [], ("accept", COV_BASE_ATTR)),
    (
        "ucov-unknown-trailing",
        "ucov",
        [Insert(14, UNKNOWN_CONTEXT_9)],
        ("accept", COV_BASE_ATTR),
    ),
    ("ucov-pid-retagged", "ucov", [Retag(0, 9)], ("reject",)),
    ("ucov-initiating-device-retagged", "ucov", [Retag(1, 9)], ("reject",)),
    ("ucov-monitored-object-retagged", "ucov", [Retag(2, 9)], ("reject",)),
    ("ucov-monitored-object-retagged-onto-time", "ucov", [Retag(2, 3)], ("reject",)),
    ("ucov-time-remaining-retagged", "ucov", [Retag(3, 8)], ("reject",)),
    ("ucov-monobj-length-truncated", "ucov", [SetLvt(2, 3)], ("reject",)),
    ("ucov-list-opening-retagged", "ucov", [Retag(4, 5)], ("reject",)),
    ("ucov-list-closing-dropped", "ucov", [Drop(13)], ("reject",)),
    ("ucov-list-closing-retagged", "ucov", [Retag(13, 3)], ("reject",)),
    ("ucov-value1-opening-retagged", "ucov", [Retag(6, 3)], ("reject",)),
    ("ucov-value1-closing-dropped", "ucov", [Drop(8)], ("reject",)),
    ("ucov-value1-closing-retagged", "ucov", [Retag(8, 4)], ("reject",)),
    ("ucov-inner-propid-retagged", "ucov", [Retag(5, 7)], ("reject",)),
    ("ucov-value2-opening-becomes-closing", "ucov", [SetLvt(10, 7)], ("reject",)),
    ("ucov-value-escape-attempt", "ucov", [Drop(8), Retag(12, 2)], ("reject",)),
    # --- Confirmed COV notification ---
    ("ccov-baseline", "ccov", [], ("accept", COV_BASE_ATTR)),
    ("ccov-monitored-object-retagged", "ccov", [Retag(2, 9)], ("reject",)),
    ("ccov-list-closing-dropped", "ccov", [Drop(13)], ("reject",)),
]


@pytest.mark.parametrize(
    "case_name,spec_name,mutations,expectation",
    DETERMINISTIC_CASES,
    ids=[case[0] for case in DETERMINISTIC_CASES],
)
async def test_tag_misalignment_deterministic(
    case_name, spec_name, mutations, expectation
):
    spec = MESSAGE_SPECS[spec_name]
    payload = apply_mutations(spec.payload, mutations)

    try:
        oracle_attr = run_oracle(spec.layout, payload)
    except OracleReject as err:
        oracle_attr = None
        oracle_error = str(err)

    sut = await run_sut(spec, payload)

    if expectation[0] == "accept":
        expected = expectation[1]
        assert (
            oracle_attr is not None
        ), f"{case_name}: oracle rejected a legal variant: {oracle_error}"
        if spec.service == "writeProperty":
            assert expected_write_attribution(oracle_attr) == expected
        else:
            assert expected_cov_attribution(oracle_attr) == expected
        assert sut.accepted, f"{case_name}: legal variant was rejected: {sut.error}"
        actual = (
            sut.write_attribution
            if spec.service == "writeProperty"
            else sut.cov_attribution
        )
        assert (
            actual == expected
        ), f"{case_name}: attribution {actual!r} != independent expectation {expected!r}"
    else:
        if expectation[0] == "reject":
            assert (
                oracle_attr is None
            ), f"{case_name}: oracle accepted a corrupt variant: {oracle_attr!r}"
        assert not sut.accepted, f"{case_name}: corrupt variant was accepted"
        assert (
            not sut.side_effect
        ), f"{case_name}: rejected variant produced a side effect: {sut}"


# ---------------------------------------------------------------------------
# Seeded mutation fuzzing with counterexample minimization
# ---------------------------------------------------------------------------


def _random_mutation(rng: random.Random, payload: bytes) -> Optional[Mutation]:
    try:
        toks = tokenize(payload)
    except OracleReject:
        return None
    roll = rng.random()
    if roll < 0.30:
        return Retag(rng.randrange(len(toks)), rng.randrange(15))
    if roll < 0.55:
        return SetLvt(rng.randrange(len(toks)), rng.randrange(8))
    if roll < 0.80:
        return Drop(rng.randrange(len(toks)))
    k = rng.randrange(15)
    raw = rng.choice(
        [
            bytes([(k << 4) | 0x0E]),
            bytes([(k << 4) | 0x0F]),
            bytes([(k << 4) | 0x09, rng.randrange(256)]),
        ]
    )
    return Insert(rng.randrange(len(toks) + 1), raw)


async def _shrink(
    spec: MessageSpec, mutations: List[Mutation], kind: str
) -> Tuple[List[Mutation], bytes]:
    """Greedily remove mutations while the same finding kind reproduces."""
    muts = list(mutations)
    i = 0
    while i < len(muts) and len(muts) > 1:
        candidate = muts[:i] + muts[i + 1 :]
        try:
            payload = apply_mutations(spec.payload, candidate)
        except (OracleReject, IndexError):
            i += 1
            continue
        finding, _, _ = await evaluate(spec, payload)
        if finding is not None and finding.kind == kind:
            muts = candidate
        else:
            i += 1
    return muts, apply_mutations(spec.payload, muts)


def _save_finding(
    seed: int,
    iteration: int,
    finding: Finding,
    spec: MessageSpec,
    mutations: List[Mutation],
    minimal_payload: bytes,
) -> Path:
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"finding-{seed:08x}-{iteration:04d}-{finding.kind}"
    (FINDINGS_DIR / f"{stem}.bin").write_bytes(spec.header + minimal_payload)
    meta = {
        "seed": seed,
        "iteration": iteration,
        "kind": finding.kind,
        "detail": finding.detail,
        "message": spec.name,
        "mutations": [m.describe() for m in mutations],
        "oracle": finding.oracle,
        "sut": finding.sut,
        "original_payload_hex": spec.payload.hex(),
        "minimal_payload_hex": minimal_payload.hex(),
        "wire_hex": (spec.header + minimal_payload).hex(),
    }
    path = FINDINGS_DIR / f"{stem}.json"
    path.write_text(json.dumps(meta, indent=2))
    return path


async def test_tag_misalignment_seeded_fuzz():
    rng = random.Random(FUZZ_SEED)
    findings: List[str] = []

    for iteration in range(FUZZ_ITERATIONS):
        spec = MESSAGE_SPECS[rng.choice(sorted(MESSAGE_SPECS))]
        mutations: List[Mutation] = []
        payload = spec.payload
        for _ in range(rng.randint(1, 3)):
            mutation = _random_mutation(rng, payload)
            if mutation is None:
                break
            mutations.append(mutation)
            payload = mutation.apply(payload)
        if not mutations:
            continue

        finding, oracle_verdict, sut = await evaluate(spec, payload)
        if finding is None:
            continue

        finding.mutations = mutations
        minimal_mutations, minimal_payload = await _shrink(
            spec, mutations, finding.kind
        )
        path = _save_finding(
            FUZZ_SEED, iteration, finding, spec, minimal_mutations, minimal_payload
        )
        findings.append(
            f"{finding.kind} at iteration {iteration} "
            f"(seed={FUZZ_SEED}): {finding.detail} -> {path}"
        )

    assert not findings, (
        f"{len(findings)} tag misalignment finding(s) "
        f"(seed={FUZZ_SEED}, counterexamples in {FINDINGS_DIR}):\n"
        + "\n".join(findings)
    )
