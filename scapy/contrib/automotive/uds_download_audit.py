"""
Offline UDS download evidence tracker.

This module replays a recorded diagnostic transcript (no vehicle access)
to distinguish "data was sent" from "a complete transfer was confirmed"
for the UDS download sequence: RequestDownload (0x34), TransferData (0x36)
and RequestTransferExit (0x37). Only uncompressed and unencrypted
transfers (dataFormatIdentifier == 0x00) are evaluated.

The collector provides the transcript already filtered to one endpoint
(tester/ECU address pair) plus the diagnostic session identifier the
download is attributed to. Evidence rules:

- A block only becomes confirmed when a matching
  TransferDataPositiveResponse echoes its blockSequenceCounter.
- A negative response with NRC 0x78 (requestCorrectlyReceived-
  ResponsePending) keeps the block pending; it is not a success.
- Retransmitted requests and duplicate positive responses are detected
  and never accumulated twice.
- The blockSequenceCounter wraps from 0xFF to 0x00.
- If the session prerequisite is missing or intermediate frames are
  lost, the affected state stays "unknown" instead of being assumed.
- An observed SecurityAccess positive response is recorded, but it is
  not evidence that the flashed image is trustworthy.

Even a "complete" result only proves the transfer finished on the wire.
It does not prove the firmware's origin, integrity against the intended
image, or safe execution.
"""

from scapy.contrib.automotive.uds import (
    UDS,
    UDS_DSC,
    UDS_DSCPR,
    UDS_NR,
    UDS_RD,
    UDS_RDPR,
    UDS_RTE,
    UDS_RTEPR,
    UDS_SAPR,
    UDS_TD,
    UDS_TDPR,
)
from scapy.packet import NoPayload

__all__ = ["UDS_DownloadEvidenceTracker"]


class UDS_DownloadEvidenceTracker(object):
    """Track confirmed download evidence in an offline UDS transcript.

    :param session: diagnosticSessionType value the collector attributes
        the download to (e.g. 0x02 for programmingSession).
    """

    def __init__(self, session):
        # type: (int) -> None
        self.session = session
        self.session_state = "unknown"  # unknown | confirmed
        self.security_access_observed = False
        self.download = None
        self.download_state = "not_observed"
        # not_observed | pending | accepted | rejected | unsupported
        self.expected_counter = 1
        self.pending_block = None
        self.confirmed_ranges = []
        self.confirmed_counters = set()
        self.confirmed_bytes = 0
        self.gap = False
        self.unverifiable = []
        self.exit_state = "not_observed"
        # not_observed | requested | pending | confirmed | refused
        self.session_prerequisite_noted = False
        self.notes = []

    def _session_ready(self):
        if self.session_state == "confirmed":
            return True
        if not self.session_prerequisite_noted:
            self.session_prerequisite_noted = True
            self.notes.append(
                "session 0x%02x was never confirmed in this transcript; "
                "download frames cannot be attributed to it"
                % self.session)
        return False

    def feed(self, data, from_tester):
        """Consume one transcript frame.

        :param data: raw UDS payload bytes or a dissected UDS packet.
        :param from_tester: True for tester->ECU, False for ECU->tester.
        """
        pkt = UDS(bytes(data)) if isinstance(data, (bytes, bytearray)) \
            else data
        if isinstance(pkt, UDS):
            if isinstance(pkt.payload, NoPayload):
                # A bare service byte (e.g. RequestTransferExit without
                # parameter record) leaves nothing to dissect into the
                # bound service class.
                if pkt.service == 0x37:
                    pkt = UDS_RTE()
                elif pkt.service == 0x77:
                    pkt = UDS_RTEPR()
            else:
                pkt = pkt.payload

        if isinstance(pkt, UDS_DSC) and from_tester and \
                pkt.diagnosticSessionType != self.session:
            self.notes.append(
                "session 0x%02x requested, expected 0x%02x; frames not "
                "attributable to the audited session" % (
                    pkt.diagnosticSessionType, self.session))
        elif isinstance(pkt, UDS_DSCPR) and not from_tester:
            if pkt.diagnosticSessionType == self.session:
                self.session_state = "confirmed"
        elif isinstance(pkt, UDS_SAPR) and not from_tester:
            if not self.security_access_observed:
                self.security_access_observed = True
                self.notes.append(
                    "SecurityAccess positive response observed; this is "
                    "not evidence that the flashed image is trustworthy")
        elif isinstance(pkt, UDS_RD) and from_tester:
            if self._session_ready():
                self._feed_request_download(pkt)
        elif isinstance(pkt, UDS_RDPR) and not from_tester:
            self._feed_request_download_response(pkt)
        elif isinstance(pkt, UDS_TD) and from_tester:
            if self._session_ready():
                self._feed_transfer_data(pkt)
        elif isinstance(pkt, UDS_TDPR) and not from_tester:
            self._feed_transfer_data_response(pkt)
        elif isinstance(pkt, UDS_RTE) and from_tester:
            if self._session_ready():
                self.exit_state = "requested"
        elif isinstance(pkt, UDS_RTEPR) and not from_tester:
            if self.exit_state in ("requested", "pending"):
                self.exit_state = "confirmed"
        elif isinstance(pkt, UDS_NR) and not from_tester:
            self._feed_negative_response(pkt)

    def _feed_request_download(self, pkt):
        if pkt.dataFormatIdentifier != 0:
            self.download_state = "unsupported"
            self.notes.append(
                "dataFormatIdentifier 0x%02x: compressed/encrypted "
                "transfer is out of scope" % pkt.dataFormatIdentifier)
            return
        self.download = {
            "address": getattr(pkt, "memoryAddress%d"
                               % pkt.memoryAddressLen),
            "size": getattr(pkt, "memorySize%d" % pkt.memorySizeLen),
            "max_block_length": None,
        }
        self.download_state = "pending"

    def _feed_request_download_response(self, pkt):
        if self.download_state != "pending" or self.download is None:
            self.notes.append("RequestDownload response without pending "
                              "request; ignored")
            return
        self.download["max_block_length"] = int.from_bytes(
            bytes(pkt.maxNumberOfBlockLength), "big")
        self.download_state = "accepted"

    def _feed_transfer_data(self, pkt):
        if self.download_state != "accepted":
            self.notes.append(
                "TransferData without an accepted RequestDownload; "
                "cannot be evaluated")
            return
        counter = pkt.blockSequenceCounter
        length = len(bytes(pkt.transferRequestParameterRecord))
        max_block_length = self.download["max_block_length"]
        if max_block_length is not None and length > max_block_length - 2:
            self.gap = True
            self.notes.append(
                "block 0x%02x carries %d bytes, exceeding the negotiated "
                "maxNumberOfBlockLength %d; length accounting is "
                "unreliable" % (counter, length, max_block_length))
        if counter == self.expected_counter and self.pending_block is None:
            self.pending_block = (counter, self.confirmed_bytes, length)
        elif self.pending_block is not None and \
                counter == self.pending_block[0]:
            self.notes.append(
                "retransmission of pending block 0x%02x" % counter)
        elif counter in self.confirmed_counters:
            self.notes.append(
                "duplicate request of confirmed block 0x%02x; not "
                "accumulated" % counter)
        else:
            self.notes.append(
                "unexpected block 0x%02x while expecting 0x%02x; only a "
                "matching positive response can confirm it" % (
                    counter, self.expected_counter))

    def _feed_transfer_data_response(self, pkt):
        counter = pkt.blockSequenceCounter
        if counter in self.confirmed_counters:
            self.notes.append(
                "duplicate confirmation of block 0x%02x; not "
                "accumulated" % counter)
            return
        offset = length = None
        matched = self.pending_block is not None and \
            counter == self.pending_block[0]
        if matched:
            _, offset, length = self.pending_block
            self.pending_block = None
        if matched and not self.gap and counter == self.expected_counter:
            self.confirmed_ranges.append((offset, offset + length))
            self.confirmed_bytes += length
        else:
            self.gap = True
            self.notes.append(
                "confirmation of block 0x%02x while expecting 0x%02x: "
                "intermediate frames missing, subsequent offsets "
                "unknown" % (counter, self.expected_counter))
            self.unverifiable.append((counter, length))
        self.confirmed_counters.add(counter)
        self.expected_counter = (counter + 1) % 256

    def _feed_negative_response(self, pkt):
        service = pkt.requestServiceId
        code = pkt.negativeResponseCode
        if code == 0x78:
            if service == 0x37 and self.exit_state == "requested":
                self.exit_state = "pending"
            self.notes.append(
                "NRC requestCorrectlyReceived-ResponsePending for "
                "service 0x%02x; awaiting final response" % service)
            return
        if service == 0x36:
            if self.pending_block is not None:
                self.notes.append(
                    "block 0x%02x refused with NRC 0x%02x; not "
                    "confirmed" % (self.pending_block[0], code))
                self.pending_block = None
            else:
                self.notes.append(
                    "TransferData refused with NRC 0x%02x; not "
                    "confirmed" % code)
        elif service == 0x34:
            self.download_state = "rejected"
            self.notes.append(
                "RequestDownload rejected with NRC 0x%02x" % code)
        elif service == 0x37:
            self.exit_state = "refused"
            self.notes.append(
                "RequestTransferExit rejected with NRC 0x%02x" % code)
        elif service == 0x10:
            self.notes.append(
                "DiagnosticSessionControl rejected with NRC 0x%02x; "
                "session prerequisite unknown" % code)

    def report(self):
        """Summarize the confirmed evidence and the unprovable parts."""
        size = self.download["size"] if self.download else None
        if self.session_state != "confirmed" or self.download is None \
                or self.download_state != "accepted" or self.gap:
            status = "unknown"
        elif self.exit_state == "confirmed" and size is not None and \
                self.confirmed_bytes == size:
            status = "complete"
        else:
            status = "incomplete"

        merged = []  # type: list
        for start, end in sorted(self.confirmed_ranges):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        unconfirmed = []
        if size is not None:
            cursor = 0
            for start, end in merged:
                if start > cursor:
                    unconfirmed.append((cursor, start))
                cursor = max(cursor, end)
            if cursor < size:
                unconfirmed.append((cursor, size))

        notes = list(self.notes)
        notes.append(
            "a complete transfer does not prove the firmware's origin, "
            "that the flashed image matches the intended one, or that "
            "executing it is safe")
        return {
            "status": status,
            "session": self.session,
            "session_state": self.session_state,
            "security_access_observed": self.security_access_observed,
            "download": self.download,
            "download_state": self.download_state,
            "confirmed_ranges": merged,
            "confirmed_bytes": self.confirmed_bytes,
            "unconfirmed_ranges": unconfirmed,
            "unverifiable_blocks": list(self.unverifiable),
            "transfer_exit": self.exit_state,
            "notes": notes,
        }
