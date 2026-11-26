"""Shared contract harness for the two ``ResourceProtector`` integrations.

The Flask and Django contract test modules both run the *same* fictional
request set (:data:`FICTIONAL_REQUESTS`) through their framework adapter and
assert the *same* contract through :func:`evaluate_contract`.

Three independent observation points are kept apart on purpose:

* :class:`RecordingBearerTokenValidator` records which Authlib validation
  steps actually ran (the *validation* phase).
* :class:`ResourceCallback` records whether the protected business logic was
  invoked (the *resource* phase).
* :func:`instrument_boundary` captures the typed ``OAuth2Error`` at the shared
  ``ResourceProtector.validate_request`` boundary, *before* either framework
  converts it into an HTTP response.

The post-conversion facts are the normalized standard HTTP response
(:class:`RunResult`). Comparing the pre-conversion records with the
post-conversion response shows what each framework keeps and what conversion
drops.

Shareable evidence (:func:`build_shareable_evidence`) is an allow-listed
projection containing only ``stage``, ``classification`` and
``correlation_id``. Fictional business objects and raw credentials carry a
canary and are asserted absent from every shareable/controlled record.
"""

from __future__ import annotations

import functools
import importlib.util
import json
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from typing import Any

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749 import MissingAuthorizationError
from authlib.oauth2.rfc6749.util import scope_to_list
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750.errors import InsufficientScopeError
from authlib.oauth2.rfc6750.errors import InvalidTokenError

# A unique marker planted on the fictional business/token objects. If this
# string ever shows up in a controlled or shareable record, a business object
# leaked into evidence.
BUSINESS_CANARY = "CANARY-business-object-9f3a27e1-restricted"

# --- Approved evidence vocabulary -----------------------------------------

STAGE_PARSE_CREDENTIAL = "parse_request_authorization"
STAGE_VALIDATE_TOKEN = "validate_token"
STAGE_RESOURCE_CALLBACK = "resource_callback"

APPROVED_STAGES = frozenset(
    {
        STAGE_PARSE_CREDENTIAL,
        STAGE_VALIDATE_TOKEN,
        STAGE_RESOURCE_CALLBACK,
    }
)

CLASS_CREDENTIAL_UNAVAILABLE = "credential_unavailable"
CLASS_PERMISSION_INSUFFICIENT = "permission_insufficient"
CLASS_ACCESS_GRANTED = "access_granted"

APPROVED_CLASSIFICATIONS = frozenset(
    {
        CLASS_CREDENTIAL_UNAVAILABLE,
        CLASS_PERMISSION_INSUFFICIENT,
        CLASS_ACCESS_GRANTED,
    }
)

# The only keys a shareable evidence record is allowed to contain.
SHAREABLE_EVIDENCE_KEYS = ("stage", "classification", "correlation_id")

_ERROR_CLASSES = {
    MissingAuthorizationError.error: MissingAuthorizationError,
    InvalidTokenError.error: InvalidTokenError,
    InsufficientScopeError.error: InsufficientScopeError,
}

# Authlib error code -> (approved classification, precise stopping stage).
_ERROR_ADJUDICATION = {
    MissingAuthorizationError.error: (
        CLASS_CREDENTIAL_UNAVAILABLE,
        STAGE_PARSE_CREDENTIAL,
    ),
    InvalidTokenError.error: (
        CLASS_CREDENTIAL_UNAVAILABLE,
        STAGE_VALIDATE_TOKEN,
    ),
    InsufficientScopeError.error: (
        CLASS_PERMISSION_INSUFFICIENT,
        STAGE_VALIDATE_TOKEN,
    ),
}

# One consistent set of *fictional* tokens. These strings are fake fixtures,
# not real credentials, and the recorder never stores the raw token string.
FICTIONAL_TOKEN_SCOPES = {
    "fic-token-read": "reports:read",
    "fic-token-limited": "profile:read",
}


def case_ref_for(correlation_id: str) -> str:
    return "CASE-" + correlation_id.removeprefix("CORR-")


# --- Fictional request set --------------------------------------------------


@dataclass(frozen=True)
class ContractScenario:
    id: str
    correlation_id: str
    authorization: str | None
    required_scopes: tuple[str, ...]
    expected_status: int
    # Typed Authlib error observed before conversion; None when allowed.
    core_error_code: str | None
    # OAuth2 "error" code present on the wire body; None when the standard
    # response body intentionally carries no error code.
    wire_error: str | None
    expected_classification: str
    expected_stage: str
    expected_step_names: tuple[str, ...]
    expected_business_calls: int
    path: str = "/contract/fictional-resource"
    method: str = "GET"


_VALIDATOR_STEPS = ("validate_request", "authenticate_token", "validate_token")

FICTIONAL_REQUESTS: tuple[ContractScenario, ...] = (
    ContractScenario(
        id="credential_absent",
        correlation_id="CORR-FIC-0001",
        authorization=None,
        required_scopes=("reports:read",),
        expected_status=401,
        core_error_code=MissingAuthorizationError.error,
        wire_error=None,
        expected_classification=CLASS_CREDENTIAL_UNAVAILABLE,
        expected_stage=STAGE_PARSE_CREDENTIAL,
        # Parsing the Authorization header fails before any validator method.
        expected_step_names=(),
        expected_business_calls=0,
    ),
    ContractScenario(
        id="credential_unsupported_scheme",
        correlation_id="CORR-FIC-0002",
        authorization="MysteryScheme fic-token-attempt",
        required_scopes=("reports:read",),
        expected_status=401,
        core_error_code=MissingAuthorizationError.error,
        wire_error=None,
        expected_classification=CLASS_CREDENTIAL_UNAVAILABLE,
        expected_stage=STAGE_PARSE_CREDENTIAL,
        expected_step_names=(),
        expected_business_calls=0,
    ),
    ContractScenario(
        id="credential_token_unresolvable",
        correlation_id="CORR-FIC-0003",
        authorization="Bearer fic-token-unknown",
        required_scopes=("reports:read",),
        expected_status=401,
        core_error_code=InvalidTokenError.error,
        wire_error=InvalidTokenError.error,
        expected_classification=CLASS_CREDENTIAL_UNAVAILABLE,
        expected_stage=STAGE_VALIDATE_TOKEN,
        expected_step_names=_VALIDATOR_STEPS,
        expected_business_calls=0,
    ),
    ContractScenario(
        id="permission_insufficient_scope",
        correlation_id="CORR-FIC-0004",
        authorization="Bearer fic-token-limited",
        required_scopes=("reports:read",),
        expected_status=403,
        core_error_code=InsufficientScopeError.error,
        wire_error=InsufficientScopeError.error,
        expected_classification=CLASS_PERMISSION_INSUFFICIENT,
        expected_stage=STAGE_VALIDATE_TOKEN,
        expected_step_names=_VALIDATOR_STEPS,
        expected_business_calls=0,
    ),
    ContractScenario(
        id="access_granted",
        correlation_id="CORR-FIC-0005",
        authorization="Bearer fic-token-read",
        required_scopes=("reports:read",),
        expected_status=200,
        core_error_code=None,
        wire_error=None,
        expected_classification=CLASS_ACCESS_GRANTED,
        expected_stage=STAGE_RESOURCE_CALLBACK,
        expected_step_names=_VALIDATOR_STEPS,
        expected_business_calls=1,
    ),
)

DENIAL_SCENARIOS = tuple(s for s in FICTIONAL_REQUESTS if s.core_error_code)


# --- Fictional business/token objects --------------------------------------


@dataclass
class FictionalBusinessObject:
    """The protected application object.

    It deliberately carries a canary in ``restricted_note``. Only its public
    ``case_ref`` projection may reach a response/record.
    """

    case_ref: str
    owner_alias: str = "fictional-support-queue"
    restricted_note: str = BUSINESS_CANARY


@dataclass
class FictionalToken:
    scope: str
    subject_alias: str = "fictional-subject"
    restricted_claim: str = BUSINESS_CANARY

    def is_expired(self) -> bool:
        return False

    def is_revoked(self) -> bool:
        return False

    def get_scope(self) -> str:
        return self.scope


def business_object_for(scenario: ContractScenario) -> FictionalBusinessObject:
    return FictionalBusinessObject(case_ref=case_ref_for(scenario.correlation_id))


# --- Recording doubles ------------------------------------------------------


@dataclass
class Ledger:
    """Primitive-only observation log (never stores token/business objects)."""

    validator_steps: list[dict[str, Any]] = field(default_factory=list)
    boundary_errors: list[dict[str, Any]] = field(default_factory=list)

    def add_step(self, step: str, **facts: Any) -> None:
        self.validator_steps.append({"step": step, **facts})

    def add_boundary_error(self, error: OAuth2Error) -> None:
        self.boundary_errors.append(
            {
                "type": type(error).__name__,
                "code": getattr(error, "error", None),
                "status_code": getattr(error, "status_code", None),
            }
        )

    @property
    def step_names(self) -> list[str]:
        return [str(step["step"]) for step in self.validator_steps]


class RecordingBearerTokenValidator(BearerTokenValidator):
    """A bearer validator that records each phase and uses real Authlib checks."""

    def __init__(
        self,
        token_scopes: dict[str, str],
        ledger: Ledger,
        realm: str | None = None,
    ) -> None:
        super().__init__(realm)
        self._token_scopes = token_scopes
        self._ledger = ledger

    def validate_request(self, request: Any) -> None:
        self._ledger.add_step("validate_request")

    def authenticate_token(self, token_string: str) -> FictionalToken | None:
        scope = self._token_scopes.get(token_string)
        token = FictionalToken(scope=scope) if scope is not None else None
        self._ledger.add_step(
            "authenticate_token",
            credential_present=bool(token_string),
            lookup="hit" if token is not None else "miss",
        )
        return token

    def validate_token(
        self, token: FictionalToken | None, scopes: Any, request: Any, **kwargs: Any
    ) -> None:
        required = scope_to_list(scopes) or []
        self._ledger.add_step(
            "validate_token",
            token_present=token is not None,
            required_scopes=[str(item) for item in required],
        )
        # Delegate to the genuine RFC 6750 checks so real errors are raised.
        super().validate_token(token, scopes, request)


class ResourceCallback:
    """Records whether the protected business operation actually ran."""

    def __init__(self, business_object: FictionalBusinessObject) -> None:
        self.business_object = business_object
        self.calls = 0

    def payload(self) -> dict[str, str]:
        self.calls += 1
        # Public projection only; ``restricted_note`` is intentionally absent.
        return {"case_ref": self.business_object.case_ref, "state": "processed"}


def instrument_boundary(protector: Any, ledger: Ledger) -> Any:
    """Record the typed ``OAuth2Error`` before framework error conversion."""
    original_validate_request = protector.validate_request

    @functools.wraps(original_validate_request)
    def validate_request(*args: Any, **kwargs: Any) -> Any:
        try:
            return original_validate_request(*args, **kwargs)
        except OAuth2Error as error:
            ledger.add_boundary_error(error)
            raise

    # An instance attribute shadows the class method; the closure keeps the
    # original bound method, so no implicit ``self`` is injected here.
    protector.validate_request = validate_request
    return protector


class StatusOnlyProtectorDouble:
    """Mutated test double that skips validation.

    It exposes the same decorator surface as a ``ResourceProtector`` but
    short-circuits every protected call with the *same* standard error response
    status/body/headers. It deliberately performs no validation and therefore
    writes no validator steps and no pre-conversion boundary record. A test
    that only compares the HTTP response cannot tell this double from the real
    protector; :func:`evaluate_contract` detects it from calls and records.
    """

    def __init__(self, scenario: ContractScenario, respond: Any) -> None:
        self._scenario = scenario
        self._respond = respond

    def __call__(
        self, scopes: Any = None, optional: bool = False, **kwargs: Any
    ) -> Any:
        def decorator(function: Any) -> Any:
            @functools.wraps(function)
            def wrapper(*args: Any, **call_kwargs: Any) -> Any:
                code = self._scenario.core_error_code
                if code is None:
                    return function(*args, **call_kwargs)
                error = _error_instance(code)
                return self._respond(
                    error.status_code,
                    dict(error.get_body()),
                    list(error.get_headers()),
                )

            return wrapper

        if callable(scopes):
            return decorator(scopes)
        return decorator


# --- Normalized run result --------------------------------------------------


@dataclass
class RunResult:
    framework: str
    mode: str
    scenario_id: str
    status_code: int
    body: Any
    headers: dict[str, str]
    validator_steps: list[dict[str, Any]]
    boundary_errors: list[dict[str, Any]]
    business_calls: int

    @property
    def step_names(self) -> list[str]:
        return [str(step["step"]) for step in self.validator_steps]


# --- Framework availability / setup ----------------------------------------


def flask_available() -> bool:
    return importlib.util.find_spec("flask") is not None


def django_available() -> bool:
    return importlib.util.find_spec("django") is not None


def ensure_django() -> Any:
    """Configure minimal Django settings when pytest-django has not done so."""
    import django
    from django.conf import settings

    if not settings.configured:
        settings.configure(
            DEBUG=True,
            SECRET_KEY="contract-test-secret",
            DATABASES={},
            INSTALLED_APPS=[],
            ALLOWED_HOSTS=["testserver"],
            USE_TZ=True,
        )
        django.setup()
    return django


# --- Standard response oracle ----------------------------------------------


def _error_instance(code: str) -> OAuth2Error:
    return _ERROR_CLASSES[code]()


def standard_wire_facts(scenario: ContractScenario) -> dict[str, Any]:
    """The standard HTTP facts the real integration is required to preserve."""
    if scenario.core_error_code is None:
        return {
            "status": 200,
            "body": {
                "case_ref": case_ref_for(scenario.correlation_id),
                "state": "processed",
            },
            "content_type": "application/json",
            "www_authenticate": None,
        }
    error = _error_instance(scenario.core_error_code)
    header_map = {name.lower(): value for name, value in error.get_headers()}
    return {
        "status": error.status_code,
        "body": dict(error.get_body()),
        "content_type": "application/json",
        "www_authenticate": header_map.get("www-authenticate"),
    }


def wire_facts(run: RunResult) -> dict[str, Any]:
    content_type = (run.headers.get("content-type") or "").split(";", 1)[0].strip()
    return {
        "status": run.status_code,
        "body": run.body,
        "content_type": content_type,
        "www_authenticate": run.headers.get("www-authenticate"),
    }


def pre_conversion_facts(run: RunResult) -> dict[str, Any]:
    return {
        "boundary_errors": run.boundary_errors,
        "validator_steps": run.step_names,
        "business_calls": run.business_calls,
    }


# --- Framework adapters -----------------------------------------------------


def _request_headers(scenario: ContractScenario) -> dict[str, str]:
    if scenario.authorization:
        return {"Authorization": scenario.authorization}
    return {}


def run_flask(scenario: ContractScenario, bypass: bool = False) -> RunResult:
    from flask import Flask
    from flask import jsonify

    from authlib.integrations.flask_oauth2 import ResourceProtector

    ledger = Ledger()
    callback = ResourceCallback(business_object_for(scenario))

    app = Flask(__name__)
    app.testing = True

    if bypass:

        def respond(
            status: int, body: dict[str, Any], headers: list[tuple[str, str]]
        ) -> Any:
            return jsonify(body), status, headers

        protector: Any = StatusOnlyProtectorDouble(scenario, respond)
        mode = "status_only_bypass"
    else:
        protector = ResourceProtector()
        protector.register_token_validator(
            RecordingBearerTokenValidator(FICTIONAL_TOKEN_SCOPES, ledger)
        )
        instrument_boundary(protector, ledger)
        mode = "real"

    @app.route(scenario.path, methods=[scenario.method])
    @protector(list(scenario.required_scopes))
    def resource() -> Any:
        return callback.payload()

    client = app.test_client()
    response = client.get(scenario.path, headers=_request_headers(scenario))

    return RunResult(
        framework="flask",
        mode=mode,
        scenario_id=scenario.id,
        status_code=response.status_code,
        body=response.get_json(),
        headers={key.lower(): value for key, value in response.headers.items()},
        validator_steps=ledger.validator_steps,
        boundary_errors=ledger.boundary_errors,
        business_calls=callback.calls,
    )


def run_django(scenario: ContractScenario, bypass: bool = False) -> RunResult:
    ensure_django()

    from django.http import JsonResponse
    from django.test import RequestFactory

    from authlib.integrations.django_oauth2.resource_protector import ResourceProtector

    ledger = Ledger()
    callback = ResourceCallback(business_object_for(scenario))

    if bypass:

        def respond(
            status: int, body: dict[str, Any], headers: list[tuple[str, str]]
        ) -> Any:
            response = JsonResponse(body, status=status)
            for key, value in headers:
                response[key] = value
            return response

        protector: Any = StatusOnlyProtectorDouble(scenario, respond)
        mode = "status_only_bypass"
    else:
        protector = ResourceProtector()
        protector.register_token_validator(
            RecordingBearerTokenValidator(FICTIONAL_TOKEN_SCOPES, ledger)
        )
        instrument_boundary(protector, ledger)
        mode = "real"

    @protector(list(scenario.required_scopes))
    def resource_view(request: Any) -> JsonResponse:
        return JsonResponse(callback.payload(), status=200)

    factory = RequestFactory()
    if scenario.authorization:
        request = factory.get(scenario.path, HTTP_AUTHORIZATION=scenario.authorization)
    else:
        request = factory.get(scenario.path)

    response = resource_view(request)

    return RunResult(
        framework="django",
        mode=mode,
        scenario_id=scenario.id,
        status_code=response.status_code,
        body=json.loads(response.content.decode("utf-8")),
        headers={key.lower(): value for key, value in response.items()},
        validator_steps=ledger.validator_steps,
        boundary_errors=ledger.boundary_errors,
        business_calls=callback.calls,
    )


def run_for(
    framework: str, scenario: ContractScenario, bypass: bool = False
) -> RunResult:
    if framework == "flask":
        return run_flask(scenario, bypass=bypass)
    if framework == "django":
        return run_django(scenario, bypass=bypass)
    raise ValueError(f"unknown framework: {framework!r}")


# --- Adjudication + contract evaluation ------------------------------------


def adjudicate(
    boundary_errors: list[dict[str, Any]],
) -> tuple[str, str]:
    """Return (stage, approved_classification) from pre-conversion records."""
    if not boundary_errors:
        return STAGE_RESOURCE_CALLBACK, CLASS_ACCESS_GRANTED
    code = boundary_errors[0]["code"]
    classification, stage = _ERROR_ADJUDICATION[code]
    return stage, classification


def evaluate_contract(scenario: ContractScenario, run: RunResult) -> list[str]:
    """Return a list of contract violations; empty means the contract holds.

    Every check is independent so a mutated double reports all missing
    observations rather than failing on the first assertion.
    """
    violations: list[str] = []
    expected_wire = standard_wire_facts(scenario)
    actual_wire = wire_facts(run)

    if actual_wire["status"] != expected_wire["status"]:
        violations.append(
            f"status: expected {expected_wire['status']}, got {actual_wire['status']}"
        )

    if actual_wire["body"] != expected_wire["body"]:
        violations.append(
            "standard response body mismatch: "
            f"expected {expected_wire['body']!r}, got {actual_wire['body']!r}"
        )

    if actual_wire["content_type"] != expected_wire["content_type"]:
        violations.append(
            "content type: expected application/json, "
            f"got {actual_wire['content_type']!r}"
        )

    if actual_wire["www_authenticate"] != expected_wire["www_authenticate"]:
        violations.append(
            "WWW-Authenticate mismatch: "
            f"expected {expected_wire['www_authenticate']!r}, "
            f"got {actual_wire['www_authenticate']!r}"
        )

    # --- Pre-conversion boundary record ------------------------------------
    if scenario.core_error_code is None:
        if run.boundary_errors:
            violations.append(
                "pre-conversion boundary record: expected no OAuth2Error, "
                f"got {run.boundary_errors!r}"
            )
    else:
        if len(run.boundary_errors) != 1:
            violations.append(
                "pre-conversion boundary record: expected exactly one captured "
                f"OAuth2Error for {scenario.core_error_code!r}, "
                f"got {run.boundary_errors!r}; validation/error conversion was "
                "skipped and cannot be evidenced before conversion"
            )
        else:
            boundary = run.boundary_errors[0]
            if boundary["code"] != scenario.core_error_code:
                violations.append(
                    "pre-conversion boundary code: expected "
                    f"{scenario.core_error_code!r}, got {boundary['code']!r}"
                )
            if boundary["status_code"] != scenario.expected_status:
                violations.append(
                    "pre-conversion boundary status: expected "
                    f"{scenario.expected_status}, got {boundary['status_code']}"
                )

    # --- Recording validator call ledger -----------------------------------
    actual_steps = [str(step["step"]) for step in run.validator_steps]
    if actual_steps != list(scenario.expected_step_names):
        violations.append(
            "recording validator calls: expected step sequence "
            f"{list(scenario.expected_step_names)!r}, got {actual_steps!r}; "
            "the test double skipped Authlib validation"
        )

    # --- Protected resource/business callback ------------------------------
    if run.business_calls != scenario.expected_business_calls:
        violations.append(
            "resource callback / protected business calls: expected "
            f"{scenario.expected_business_calls}, got {run.business_calls}; "
            "protected business was invoked incorrectly"
        )

    # --- Adjudicated stage/classification must agree with the scenario -----
    stage, classification = adjudicate(run.boundary_errors)
    if stage != scenario.expected_stage:
        violations.append(
            f"stage: expected {scenario.expected_stage!r}, got {stage!r} "
            "(from pre-conversion records)"
        )
    if classification != scenario.expected_classification:
        violations.append(
            "approved classification: expected "
            f"{scenario.expected_classification!r}, got {classification!r}"
        )

    return violations


def assert_contract(scenario: ContractScenario, run: RunResult) -> None:
    violations = evaluate_contract(scenario, run)
    if violations:
        bullet_list = "\n  - ".join(violations)
        raise AssertionError(
            f"ResourceProtector contract violated for {scenario.id} "
            f"on {run.framework} ({run.mode}):\n  - {bullet_list}"
        )


# --- Shareable evidence -----------------------------------------------------


def build_shareable_evidence(
    scenario: ContractScenario, run: RunResult
) -> dict[str, str]:
    stage, classification = adjudicate(run.boundary_errors)
    # Explicit allow-listed projection: nothing but these three keys.
    return {
        "stage": stage,
        "classification": classification,
        "correlation_id": scenario.correlation_id,
    }


def evidence_violations(
    evidence: dict[str, Any], scenario: ContractScenario
) -> list[str]:
    violations: list[str] = []
    if tuple(evidence.keys()) != SHAREABLE_EVIDENCE_KEYS:
        violations.append(
            "shareable evidence fields: expected exactly "
            f"{list(SHAREABLE_EVIDENCE_KEYS)}, got {list(evidence.keys())}"
        )

    if evidence.get("stage") not in APPROVED_STAGES:
        violations.append(f"stage {evidence.get('stage')!r} is not approved")

    if evidence.get("classification") not in APPROVED_CLASSIFICATIONS:
        violations.append(
            f"classification {evidence.get('classification')!r} is not approved"
        )

    if evidence.get("correlation_id") != scenario.correlation_id:
        violations.append(
            "correlation_id mismatch: expected "
            f"{scenario.correlation_id!r}, got {evidence.get('correlation_id')!r}"
        )

    expected = {
        "stage": scenario.expected_stage,
        "classification": scenario.expected_classification,
        "correlation_id": scenario.correlation_id,
    }
    if evidence != expected:
        violations.append(f"shareable evidence mismatch: expected {expected!r}")

    serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
    if BUSINESS_CANARY in serialized:
        violations.append("business object canary leaked into shareable evidence")

    return violations


def record_leak_violations(
    scenario: ContractScenario, run: RunResult, evidence: dict[str, str]
) -> list[str]:
    """Ensure business objects and raw credentials stay out of all records."""
    violations: list[str] = []

    controlled_blob = json.dumps(asdict(run), ensure_ascii=False, default=str)
    if BUSINESS_CANARY in controlled_blob:
        violations.append(
            "business object canary leaked into the controlled run records"
        )

    evidence_blob = json.dumps(evidence, ensure_ascii=False, default=str)
    if BUSINESS_CANARY in evidence_blob:
        violations.append("business object canary leaked into shareable evidence")

    if scenario.authorization and " " in scenario.authorization:
        raw_credential = scenario.authorization.split(" ", 1)[1]
        if raw_credential and raw_credential in controlled_blob:
            violations.append(
                "raw credential value must not be stored in call/evidence records"
            )

    return violations
