"""Raw-byte PFCP transcripts used as audit input.

Transcripts are intentionally just labelled hexadecimal byte strings: they are
the captured evidence, independent of any audit interpretation.  Keeping the
loader dumb (hex decode plus a direction/label) avoids any chance that the
checker normalizes away a malformed or truncated message before auditing it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


@dataclass
class TranscriptMessage:
    """One captured PFCP message: a label, a direction and the raw bytes."""

    label: str
    direction: str
    bytes: bytes

    @property
    def hex(self) -> str:
        return self.bytes.hex()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'label': self.label,
            'direction': self.direction,
            'hex': self.hex,
        }


@dataclass
class Transcript:
    """An ordered capture of PFCP messages, possibly spanning sessions."""

    name: str
    description: str
    messages: List[TranscriptMessage]

    def __iter__(self):
        return iter(self.messages)

    def __len__(self) -> int:
        return len(self.messages)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'description': self.description,
            'messages': [m.to_dict() for m in self.messages],
        }


def _coerce_bytes(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        cleaned = value.replace(' ', '').replace('\n', '').replace('\t', '').strip()
        return bytes.fromhex(cleaned)
    raise TypeError('transcript message body must be hex str or bytes')


def load_transcript(spec: Dict[str, Any]) -> Transcript:
    """Build a transcript from a plain JSON-like dictionary."""
    messages: List[TranscriptMessage] = []
    for item in spec.get('messages', []):
        messages.append(
            TranscriptMessage(
                label=str(item['label']),
                direction=str(item.get('direction', '?')),
                bytes=_coerce_bytes(item['hex']),
            )
        )
    return Transcript(
        name=str(spec.get('name', 'unnamed')),
        description=str(spec.get('description', '')),
        messages=messages,
    )


def load_transcripts(specs: Iterable[Dict[str, Any]]) -> List[Transcript]:
    return [load_transcript(spec) for spec in specs]
