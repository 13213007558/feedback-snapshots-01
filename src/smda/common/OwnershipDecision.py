"""Evidence for one function-ownership decision taken during CFG recovery.

When a branch target is merged into the function being analyzed, kept as a
tailcall, split off its previous owner, or refused as a candidate, an
OwnershipDecision preserves what the decision saw: the branch it concerns,
the function under analysis, the owner the target's bytes already belonged
to, and the candidate evidence (sources and characteristics) at the involved
addresses. Records are append-only evidence for the reverse engineering
workflow; they never change ownership themselves, so the IDA-style model
(every instruction owned by exactly one function, no overlap) stays intact.
"""


class OwnershipDecision:
    def __init__(
        self,
        decision,
        basis,
        target_addr,
        source_addr=None,
        function_addr=None,
        previous_owner=None,
        candidates=None,
    ):
        #: what was decided: "absorbed", "tailcall", "deferred", "stub", "split",
        #: "reverted", "restored", "reanalyzed" or "refused"
        self.decision = decision
        #: machine-readable reason the decision was taken (e.g. "jump_into_owned_function_body")
        self.basis = basis
        #: address the decision is about (usually a branch target or a candidate start)
        self.target_addr = target_addr
        #: address of the branch instruction that raised the decision, if any
        self.source_addr = source_addr
        #: function being analyzed when the decision was taken
        self.function_addr = function_addr
        #: function that owned the target's bytes before the decision, if any
        self.previous_owner = previous_owner
        #: candidate evidence snapshots at the involved addresses, keyed by address
        self.candidates = candidates if candidates is not None else {}

    @staticmethod
    def snapshotCandidate(candidate):
        """Capture a candidate's discovery evidence: who referenced it and on what grounds it stands."""
        return {
            "characteristics": candidate.getCharacteristics(),
            "call_ref_sources": sorted(candidate.call_ref_sources),
            "prologue_score": candidate.getFunctionStartScore(),
        }

    def toDict(self):
        return {
            "decision": self.decision,
            "basis": self.basis,
            "target_addr": self.target_addr,
            "source_addr": self.source_addr,
            "function_addr": self.function_addr,
            "previous_owner": self.previous_owner,
            "candidates": self.candidates,
        }

    @classmethod
    def fromDict(cls, decision_dict):
        if not isinstance(decision_dict, dict):
            raise ValueError("serialized ownership decision must be a dictionary")
        candidates = decision_dict.get("candidates") or {}
        if not isinstance(candidates, dict):
            raise ValueError("serialized ownership decision candidates must be a dictionary")
        return cls(
            decision_dict["decision"],
            decision_dict["basis"],
            decision_dict["target_addr"],
            source_addr=decision_dict.get("source_addr"),
            function_addr=decision_dict.get("function_addr"),
            previous_owner=decision_dict.get("previous_owner"),
            candidates={int(addr): snapshot for addr, snapshot in candidates.items()},
        )

    def __eq__(self, other):
        if not isinstance(other, OwnershipDecision):
            return NotImplemented
        return self.toDict() == other.toDict()

    def __ne__(self, other):
        equal = self.__eq__(other)
        return equal if equal is NotImplemented else not equal

    def __repr__(self):
        return (
            f"OwnershipDecision({self.decision}, {self.basis}, "
            f"target=0x{self.target_addr:x}, owner={self.previous_owner and hex(self.previous_owner)})"
        )
