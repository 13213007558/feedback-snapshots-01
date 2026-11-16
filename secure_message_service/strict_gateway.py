"""Fail-close secure message gateway on top of asn1tools.

asn1tools' default ``decode`` never runs a constraint check and its
``encode`` only runs ``check_types``. This wrapper turns the decoder into an
admission gate whose policy is derived from the generated inventory rather
than from hope:

  * every decode is followed by ``check_constraints`` (L3);
  * any inventory entry that is not a guaranteed admission check for the
    selected codec must have an explicit registered application validator,
    otherwise construction of the gateway fails closed;
  * extension markers, WITH COMPONENTS and other silently-ignored statements
    can never be mistaken for enforced policy - they are rejected up front
    unless the application registers a concrete validator for them.

The gateway never evaluates ASN.1 constraints as generic Python expressions.
Each registered validator is an explicit, named function tied to one
inventory path.
"""

import json
from pathlib import Path

import asn1tools
from asn1tools.errors import ConstraintsError
from asn1tools.errors import DecodeError
from asn1tools.errors import EncodeError

HERE = Path(__file__).resolve().parent


class PolicyError(RuntimeError):
    """Raised at construction time when the policy cannot be made safe."""


class AdmissionError(RuntimeError):
    """Raised when a wire message fails an admission check."""


class StrictGateway:
    def __init__(self, codec, schema_path=None, inventory_path=None,
                 validators=None):
        schema_path = Path(schema_path or HERE / "protocol.asn1")
        inventory_path = Path(inventory_path or HERE / "constraint_inventory.json")
        self.codec = codec
        self.compiled = asn1tools.compile_string(schema_path.read_text(), codec)
        self.inventory = json.loads(inventory_path.read_text())
        self.pdu = self.inventory["pdu"]
        self.validators = dict(validators or {})
        self._extension_validator = None
        self._install_extension_policy()
        self._assert_policy_is_complete()

    def _install_extension_policy(self):
        """The extension-marker path always needs a validator; construct the
        codec-specific wire walker unless the application supplied one."""
        from validators import make_extension_addition_validator
        path = f"{self.pdu}.__extension_additions__"
        if path not in self.validators:
            self._extension_validator = make_extension_addition_validator(self.codec)
            self.validators[path] = self._extension_validator

    # ------------------------------------------------------------------ policy
    def _assert_policy_is_complete(self):
        """Fail closed unless every unguaranteed statement has a validator."""
        missing = []

        for entry in self.inventory["constraints"]:
            guarantee = entry["admission_guarantee"][self.codec]["strict_gateway"]
            if guarantee["guaranteed"]:
                continue
            if entry["path"] not in self.validators:
                missing.append({
                    "path": entry["path"],
                    "asn1_fragment": entry["asn1_fragment"],
                    "reason": guarantee["reason"],
                })

        for ignored in self.inventory["unsupported_or_ignored"]:
            if ignored["path"] not in self.validators:
                missing.append({
                    "path": ignored["path"],
                    "asn1_fragment": ignored["constraint"]["kind"],
                    "reason": ignored["reason"],
                })

        for marker in self.inventory["unscoped_extension_markers"]:
            path = marker["path"] + ".__extension_additions__"
            if path not in self.validators:
                missing.append({
                    "path": path,
                    "asn1_fragment": "...",
                    "reason": marker["effect"],
                })

        if missing:
            raise PolicyError(
                "Refusing to start: the following statements are not guaranteed "
                "by asn1tools for codec %r and have no registered validator:\n%s"
                % (self.codec, json.dumps(missing, indent=2, ensure_ascii=False)))

    # ------------------------------------------------------------- validators
    def _validate_tree(self, data, prefix=""):
        """Walk decoded data and invoke every registered validator by path."""
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                if path in self.validators:
                    self.validators[path](value)
                self._validate_tree(value, path)
        elif isinstance(data, (list, tuple)):
            for index, value in enumerate(data):
                path = f"{prefix}[]"
                if path in self.validators:
                    self.validators[path](value)
                self._validate_tree(value, path)

    # ------------------------------------------------------------------ public
    def receive(self, wire):
        """Decode + full admission checks. Raises AdmissionError on failure."""
        if self._extension_validator is not None:
            self._extension_validator.wire = bytes(wire)
        try:
            # L3 is mandatory here; L1 already ran inside the decoder for PER/OER.
            decoded = self.compiled.decode(
                self.pdu, bytes(wire), check_constraints=True)
        except (DecodeError, ConstraintsError) as exc:
            raise AdmissionError(f"L1/L3 rejection: {exc}") from exc

        try:
            self._validate_tree(decoded, self.pdu)
            if f"{self.pdu}.__extension_additions__" in self.validators:
                self.validators[f"{self.pdu}.__extension_additions__"](decoded)
        except (ConstraintsError, ValueError, AssertionError) as exc:
            raise AdmissionError(f"application validator rejection: {exc}") from exc

        return decoded

    def send(self, data):
        """Encode with type and constraint checks always enabled."""
        try:
            return self.compiled.encode(
                self.pdu, data,
                check_types=True, check_constraints=True)
        except (EncodeError, ConstraintsError) as exc:
            raise AdmissionError(f"outbound rejection: {exc}") from exc
