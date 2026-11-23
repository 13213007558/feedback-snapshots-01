# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pluggable Credentials.
Pluggable Credentials are initialized using external_account arguments which
are typically loaded from third-party executables. Unlike other
credentials that can be initialized with a list of explicit arguments, secrets
or credentials, external account clients use the environment and hints/guidelines
provided by the external_account JSON file to retrieve credentials and exchange
them for Google access tokens.

Example credential_source for pluggable credential:
{
    "executable": {
        "command": "/path/to/get/credentials.sh --arg1=value1 --arg2=value2",
        "timeout_millis": 5000,
        "output_file": "/path/to/generated/cached/credentials"
    }
}
"""

try:
    from collections.abc import Mapping
# Python 2.7 compatibility
except ImportError:  # pragma: NO COVER
    from collections import Mapping  # type: ignore
import hashlib
import json
import logging
import os
import shlex
import subprocess
import sys
import time

from google.auth import _helpers
from google.auth import exceptions
from google.auth import external_account

_LOGGER = logging.getLogger(__name__)

# The max supported executable spec version.
EXECUTABLE_SUPPORTED_MAX_VERSION = 1

EXECUTABLE_TIMEOUT_MILLIS_DEFAULT = 30 * 1000  # 30 seconds
EXECUTABLE_TIMEOUT_MILLIS_LOWER_BOUND = 5 * 1000  # 5 seconds
EXECUTABLE_TIMEOUT_MILLIS_UPPER_BOUND = 120 * 1000  # 2 minutes

EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_LOWER_BOUND = 30 * 1000  # 30 seconds
EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_UPPER_BOUND = 30 * 60 * 1000  # 30 minutes

# Suffix of the sidecar file recording which approved provider configuration
# the cached subject token was generated under.
PROVENANCE_FILE_SUFFIX = ".provenance"
PROVENANCE_SCHEMA_VERSION = 1


class _AdmissionDecision(object):
    """The single admission decision for one subject-token retrieval.

    The same decision governs both which subject token is returned to the
    caller and which token reaches the STS backend exchange, so an identity
    switch during a configuration change can never mix the cached identity of
    one provider with the exchange of another.

    Attributes:
        source (str): Where the admitted subject token came from. One of
            ``"cache"`` (an unexpired output file bound to the current
            configuration) or ``"executable"`` (a freshly executed provider
            command).
        subject_token (str): The admitted subject token.
        config_fingerprint (str): Fingerprint of the approved provider
            configuration the decision was made against.
        rebuilt_cache (bool): Whether the executable had to rebuild a cache
            that was missing, expired, or bound to another configuration.
    """

    CACHE = "cache"
    EXECUTABLE = "executable"

    def __init__(self, source, subject_token, config_fingerprint, rebuilt_cache):
        self.source = source
        self.subject_token = subject_token
        self.config_fingerprint = config_fingerprint
        self.rebuilt_cache = rebuilt_cache

    @property
    def admitted_from_cache(self):
        return self.source == self.CACHE


class Credentials(external_account.Credentials):
    """External account credentials sourced from executables.

    **IMPORTANT**:
    This class does not validate the credential configuration. A security
    risk occurs when a credential configuration configured with malicious urls
    is used.
    When the credential configuration is accepted from an
    untrusted source, you should validate it before using.
    Refer https://cloud.google.com/docs/authentication/external/externally-sourced-credentials for more details.
    """

    def __init__(
        self,
        audience,
        subject_token_type,
        token_url,
        credential_source,
        *args,
        **kwargs
    ):
        """Instantiates an external account credentials object from a executables.

        Args:
            audience (str): The STS audience field.
            subject_token_type (str): The subject token type.
            token_url (str): The STS endpoint URL.
            credential_source (Mapping): The credential source dictionary used to
                provide instructions on how to retrieve external credential to be
                exchanged for Google access tokens.

                Example credential_source for pluggable credential:

                    {
                        "executable": {
                            "command": "/path/to/get/credentials.sh --arg1=value1 --arg2=value2",
                            "timeout_millis": 5000,
                            "output_file": "/path/to/generated/cached/credentials"
                        }
                    }
            args (List): Optional positional arguments passed into the underlying :meth:`~external_account.Credentials.__init__` method.
            kwargs (Mapping): Optional keyword arguments passed into the underlying :meth:`~external_account.Credentials.__init__` method.

        Raises:
            google.auth.exceptions.RefreshError: If an error is encountered during
                access token retrieval logic.
            google.auth.exceptions.InvalidValue: For invalid parameters.
            google.auth.exceptions.MalformedError: For invalid parameters.

        .. note:: Typically one of the helper constructors
            :meth:`from_file` or
            :meth:`from_info` are used instead of calling the constructor directly.
        """

        self.interactive = kwargs.pop("interactive", False)
        super(Credentials, self).__init__(
            audience=audience,
            subject_token_type=subject_token_type,
            token_url=token_url,
            credential_source=credential_source,
            *args,
            **kwargs
        )
        if not isinstance(credential_source, Mapping):
            self._credential_source_executable = None
            raise exceptions.MalformedError(
                "Missing credential_source. The credential_source is not a dict."
            )
        self._credential_source_executable = credential_source.get("executable")
        if not self._credential_source_executable:
            raise exceptions.MalformedError(
                "Missing credential_source. An 'executable' must be provided."
            )
        self._credential_source_executable_command = (
            self._credential_source_executable.get("command")
        )
        self._credential_source_executable_timeout_millis = (
            self._credential_source_executable.get("timeout_millis")
        )
        self._credential_source_executable_interactive_timeout_millis = (
            self._credential_source_executable.get("interactive_timeout_millis")
        )
        self._credential_source_executable_output_file = (
            self._credential_source_executable.get("output_file")
        )

        # Dummy value. This variable is only used via injection, not exposed to ctor
        self._tokeninfo_username = ""

        # The admission decision of the most recent subject-token retrieval.
        # It is reset on every retrieval so the STS exchange that follows can
        # rely on the same decision instead of re-evaluating the cache.
        self._admission_decision = None

        if not self._credential_source_executable_command:
            raise exceptions.MalformedError(
                "Missing command field. Executable command must be provided."
            )
        if not self._credential_source_executable_timeout_millis:
            self._credential_source_executable_timeout_millis = (
                EXECUTABLE_TIMEOUT_MILLIS_DEFAULT
            )
        elif (
            self._credential_source_executable_timeout_millis
            < EXECUTABLE_TIMEOUT_MILLIS_LOWER_BOUND
            or self._credential_source_executable_timeout_millis
            > EXECUTABLE_TIMEOUT_MILLIS_UPPER_BOUND
        ):
            raise exceptions.InvalidValue("Timeout must be between 5 and 120 seconds.")

        if self._credential_source_executable_interactive_timeout_millis:
            if (
                self._credential_source_executable_interactive_timeout_millis
                < EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_LOWER_BOUND
                or self._credential_source_executable_interactive_timeout_millis
                > EXECUTABLE_INTERACTIVE_TIMEOUT_MILLIS_UPPER_BOUND
            ):
                raise exceptions.InvalidValue(
                    "Interactive timeout must be between 30 seconds and 30 minutes."
                )

    @property
    def admission_decision(self):
        """The admission decision of the most recent subject-token retrieval.

        Returns:
            Optional[google.auth.pluggable._AdmissionDecision]: The decision
            recorded by the last :meth:`retrieve_subject_token` call, or
            ``None`` before the first retrieval.
        """
        return self._admission_decision

    @property
    def config_fingerprint(self):
        """Stable fingerprint of the approved provider configuration.

        Two credential configurations produce the same fingerprint only when
        they point at the same STS audience, subject token type, and provider
        executable. It is used to tell which approved provider configuration a
        cache entry was generated for.

        Returns:
            str: The hex-encoded SHA-256 fingerprint of the configuration.
        """
        fingerprint_material = json.dumps(
            {
                "audience": self._audience,
                "subject_token_type": self._subject_token_type,
                "command": self._credential_source_executable_command,
                "output_file": (
                    str(self._credential_source_executable_output_file)
                    if self._credential_source_executable_output_file is not None
                    else None
                ),
            },
            sort_keys=True,
        )
        return hashlib.sha256(fingerprint_material.encode("utf-8")).hexdigest()

    @_helpers.copy_docstring(external_account.Credentials)
    def retrieve_subject_token(self, request):
        # A single admission decision is computed for this retrieval and reused
        # by the downstream STS exchange so both sides observe the same
        # identity during a configuration change.
        self._admission_decision = None
        config_fingerprint = self.config_fingerprint
        execution_allowed = self._is_execution_allowed()

        # Check the offline cache first. It is only admissible when it is
        # unexpired and carries provenance binding it to this exact approved
        # provider configuration.
        if self._credential_source_executable_output_file is not None:
            cached_decision = self._admit_cached_subject_token(config_fingerprint)
            if cached_decision is not None:
                self._admission_decision = cached_decision
                _LOGGER.info(
                    "Admitted cached subject token from provider configuration "
                    "%s without running the executable.",
                    config_fingerprint,
                )
                return cached_decision.subject_token

            if not execution_allowed:
                # No executable may be run in the locked-down mode and the
                # cache has no clearly attributable, still-valid entry. Stop
                # before any executable run or STS exchange.
                _LOGGER.warning(
                    "Rejecting unattributable or stale cached subject token for "
                    "provider configuration %s; executable execution is disabled.",
                    config_fingerprint,
                )
                self._validate_running_mode()

        # Reaching this point means the cache must be rebuilt through the
        # executable, which requires execution to be explicitly allowed.
        self._validate_running_mode()
        subject_token = self._run_executable_for_subject_token()

        rebuilt_cache = self._credential_source_executable_output_file is not None
        self._admission_decision = _AdmissionDecision(
            source=_AdmissionDecision.EXECUTABLE,
            subject_token=subject_token,
            config_fingerprint=config_fingerprint,
            rebuilt_cache=rebuilt_cache,
        )
        if rebuilt_cache:
            self._write_provenance(config_fingerprint)
            _LOGGER.info(
                "Rebuilt subject token cache and admitted the new subject token "
                "from provider configuration %s.",
                config_fingerprint,
            )
        else:
            _LOGGER.info(
                "Admitted a freshly executed subject token from provider "
                "configuration %s.",
                config_fingerprint,
            )
        return subject_token

    def _is_execution_allowed(self):
        return (
            os.environ.get("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES") == "1"
        )

    def _admit_cached_subject_token(self, config_fingerprint):
        """Returns a cache-sourced admission decision, or ``None``.

        The cache is admitted only when the output file parses into an
        unexpired subject token and its provenance sidecar binds it to the
        current approved provider configuration. Any mismatch, missing
        provenance, malformed content, or expiration results in ``None`` so
        the caller can either rebuild the cache or fail closed.
        """
        try:
            with open(
                self._credential_source_executable_output_file, encoding="utf-8"
            ) as output_file:
                response = json.load(output_file)
        except Exception:
            return None

        try:
            subject_token = self._parse_subject_token(response)
            if "expiration_time" not in response:
                # Always treat missing expiration_time as expired.
                raise exceptions.RefreshError
        except (exceptions.MalformedError, exceptions.InvalidValue):
            raise
        except exceptions.RefreshError:
            return None

        provenance = self._read_provenance()
        if provenance is None:
            return None
        if provenance.get("config_fingerprint") != config_fingerprint:
            _LOGGER.warning(
                "Cached subject token is bound to provider configuration %s but "
                "%s is now active; the cache is not admissible.",
                provenance.get("config_fingerprint"),
                config_fingerprint,
            )
            return None

        return _AdmissionDecision(
            source=_AdmissionDecision.CACHE,
            subject_token=subject_token,
            config_fingerprint=config_fingerprint,
            rebuilt_cache=False,
        )

    def _run_executable_for_subject_token(self):
        # Inject env vars.
        env = os.environ.copy()
        self._inject_env_variables(env)
        env["GOOGLE_EXTERNAL_ACCOUNT_REVOKE"] = "0"

        # Run executable.
        exe_timeout = (
            self._credential_source_executable_interactive_timeout_millis / 1000
            if self.interactive
            else self._credential_source_executable_timeout_millis / 1000
        )
        exe_stdin = sys.stdin if self.interactive else None
        exe_stdout = sys.stdout if self.interactive else subprocess.PIPE
        exe_stderr = sys.stdout if self.interactive else subprocess.STDOUT

        result = subprocess.run(
            shlex.split(self._credential_source_executable_command),
            timeout=exe_timeout,
            stdin=exe_stdin,
            stdout=exe_stdout,
            stderr=exe_stderr,
            env=env,
        )
        if result.returncode != 0:
            raise exceptions.RefreshError(
                "Executable exited with non-zero return code {}. Error: {}".format(
                    result.returncode, result.stdout
                )
            )

        # Handle executable output.
        response = json.loads(result.stdout.decode("utf-8")) if result.stdout else None
        if not response and self._credential_source_executable_output_file is not None:
            response = json.load(
                open(self._credential_source_executable_output_file, encoding="utf-8")
            )

        return self._parse_subject_token(response)

    def _provenance_file_path(self):
        return (
            self._credential_source_executable_output_file + PROVENANCE_FILE_SUFFIX
        )

    def _read_provenance(self):
        try:
            with open(
                self._provenance_file_path(), encoding="utf-8"
            ) as provenance_file:
                provenance = json.load(provenance_file)
        except Exception:
            return None
        if not isinstance(provenance, Mapping):
            return None
        return provenance

    def _write_provenance(self, config_fingerprint):
        provenance = {
            "version": PROVENANCE_SCHEMA_VERSION,
            "config_fingerprint": config_fingerprint,
            "audience": self._audience,
            "subject_token_type": self._subject_token_type,
            "command": self._credential_source_executable_command,
        }
        with open(
            self._provenance_file_path(), "w", encoding="utf-8"
        ) as provenance_file:
            json.dump(provenance, provenance_file)

    def revoke(self, request):
        """Revokes the subject token using the credential_source object.

        Args:
            request (google.auth.transport.Request): A callable used to make
                HTTP requests.
        Raises:
            google.auth.exceptions.RefreshError: If the executable revocation
                not properly executed.

        """
        if not self.interactive:
            raise exceptions.InvalidValue(
                "Revoke is only enabled under interactive mode."
            )
        self._validate_running_mode()

        # Inject variables
        env = os.environ.copy()
        self._inject_env_variables(env)
        env["GOOGLE_EXTERNAL_ACCOUNT_REVOKE"] = "1"

        # Run executable
        result = subprocess.run(
            shlex.split(self._credential_source_executable_command),
            timeout=self._credential_source_executable_interactive_timeout_millis
            / 1000,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
        )

        if result.returncode != 0:
            raise exceptions.RefreshError(
                "Auth revoke failed on executable. Exit with non-zero return code {}. Error: {}".format(
                    result.returncode, result.stdout
                )
            )

        response = json.loads(result.stdout.decode("utf-8"))
        self._validate_revoke_response(response)

    @property
    def external_account_id(self):
        """Returns the external account identifier.

        When service account impersonation is used the identifier is the service
        account email.

        Without service account impersonation, this returns None, unless it is
        being used by the Google Cloud CLI which populates this field.
        """

        return self.service_account_email or self._tokeninfo_username

    @classmethod
    def from_info(cls, info, **kwargs):
        """Creates a Pluggable Credentials instance from parsed external account info.

         **IMPORTANT**:
        This method does not validate the credential configuration. A security
        risk occurs when a credential configuration configured with malicious urls
        is used.
        When the credential configuration is accepted from an
        untrusted source, you should validate it before using with this method.
        Refer https://cloud.google.com/docs/authentication/external/externally-sourced-credentials for more details.

        Args:
            info (Mapping[str, str]): The Pluggable external account info in Google
                format.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.pluggable.Credentials: The constructed
                credentials.

        Raises:
            google.auth.exceptions.InvalidValue: For invalid parameters.
            google.auth.exceptions.MalformedError: For invalid parameters.
        """
        return super(Credentials, cls).from_info(info, **kwargs)

    @classmethod
    def from_file(cls, filename, **kwargs):
        """Creates an Pluggable Credentials instance from an external account json file.

        **IMPORTANT**:
        This method does not validate the credential configuration. A security
        risk occurs when a credential configuration configured with malicious urls
        is used.
        When the credential configuration is accepted from an
        untrusted source, you should validate it before using with this method.
        Refer https://cloud.google.com/docs/authentication/external/externally-sourced-credentials for more details.

        Args:
            filename (str): The path to the Pluggable external account json file.
            kwargs: Additional arguments to pass to the constructor.

        Returns:
            google.auth.pluggable.Credentials: The constructed
                credentials.
        """
        return super(Credentials, cls).from_file(filename, **kwargs)

    def _inject_env_variables(self, env):
        env["GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE"] = self._audience
        env["GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE"] = self._subject_token_type
        env["GOOGLE_EXTERNAL_ACCOUNT_ID"] = self.external_account_id
        env["GOOGLE_EXTERNAL_ACCOUNT_INTERACTIVE"] = "1" if self.interactive else "0"

        if self._service_account_impersonation_url is not None:
            env[
                "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL"
            ] = self.service_account_email
        if self._credential_source_executable_output_file is not None:
            env[
                "GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE"
            ] = self._credential_source_executable_output_file

    def _parse_subject_token(self, response):
        self._validate_response_schema(response)
        if not response["success"]:
            if "code" not in response or "message" not in response:
                raise exceptions.MalformedError(
                    "Error code and message fields are required in the response."
                )
            raise exceptions.RefreshError(
                "Executable returned unsuccessful response: code: {}, message: {}.".format(
                    response["code"], response["message"]
                )
            )
        if "expiration_time" in response and response["expiration_time"] < time.time():
            raise exceptions.RefreshError(
                "The token returned by the executable is expired."
            )
        if "token_type" not in response:
            raise exceptions.MalformedError(
                "The executable response is missing the token_type field."
            )
        if (
            response["token_type"] == "urn:ietf:params:oauth:token-type:jwt"
            or response["token_type"] == "urn:ietf:params:oauth:token-type:id_token"
        ):  # OIDC
            return response["id_token"]
        elif response["token_type"] == "urn:ietf:params:oauth:token-type:saml2":  # SAML
            return response["saml_response"]
        else:
            raise exceptions.RefreshError("Executable returned unsupported token type.")

    def _validate_revoke_response(self, response):
        self._validate_response_schema(response)
        if not response["success"]:
            raise exceptions.RefreshError("Revoke failed with unsuccessful response.")

    def _validate_response_schema(self, response):
        if "version" not in response:
            raise exceptions.MalformedError(
                "The executable response is missing the version field."
            )
        if response["version"] > EXECUTABLE_SUPPORTED_MAX_VERSION:
            raise exceptions.RefreshError(
                "Executable returned unsupported version {}.".format(
                    response["version"]
                )
            )

        if "success" not in response:
            raise exceptions.MalformedError(
                "The executable response is missing the success field."
            )

    def _validate_running_mode(self):
        env_allow_executables = os.environ.get(
            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"
        )
        if env_allow_executables != "1":
            raise exceptions.MalformedError(
                "Executables need to be explicitly allowed (set GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES to '1') to run."
            )

        if self.interactive and not self._credential_source_executable_output_file:
            raise exceptions.MalformedError(
                "An output_file must be specified in the credential configuration for interactive mode."
            )

        if (
            self.interactive
            and not self._credential_source_executable_interactive_timeout_millis
        ):
            raise exceptions.InvalidOperation(
                "Interactive mode cannot run without an interactive timeout."
            )

        if self.interactive and not self.is_workforce_pool:
            raise exceptions.InvalidValue(
                "Interactive mode is only enabled for workforce pool."
            )

    def _create_default_metrics_options(self):
        metrics_options = super(Credentials, self)._create_default_metrics_options()
        metrics_options["source"] = "executable"
        return metrics_options
