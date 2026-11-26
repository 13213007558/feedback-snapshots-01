from typing import Any

from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.models.check_error import CheckError


class ClientBatchCheckSingleResponse:
    def __init__(
        self,
        allowed: bool,
        request: ClientTuple,
        correlation_id: str,
        error: CheckError | None = None,
        confirmed: bool = True,
        response: Any | None = None,
    ) -> None:
        self._allowed = allowed
        self._request = request
        self._correlation_id = correlation_id
        self._error = error
        self._confirmed = confirmed
        self._response = response

        # Set `allowed` to `false` if there was an error and allowed isn't otherwise set.
        if error is not None and allowed is None:
            self._allowed = False

    @property
    def allowed(self) -> bool:
        """
        Return allowed
        """
        return self._allowed

    @allowed.setter
    def allowed(self, allowed: bool) -> None:
        """
        Set allowed
        """
        self._allowed = allowed

    @property
    def request(self) -> ClientTuple:
        """
        Return request
        """
        return self._request

    @request.setter
    def request(self, request: ClientTuple) -> None:
        """
        Set request
        """
        self._request = request

    @property
    def correlation_id(self) -> str:
        """
        Return correlation_id
        """
        return self._correlation_id

    @correlation_id.setter
    def correlation_id(self, correlation_id: str) -> None:
        """
        Set correlation_id
        """
        self._correlation_id = correlation_id

    @property
    def error(self) -> CheckError | None:
        """
        Return error
        """
        return self._error

    @error.setter
    def error(self, error: CheckError | None) -> None:
        """
        Set error
        """
        self._error = error

    @property
    def confirmed(self) -> bool:
        """
        Return whether this response is authoritative for the request.

        A response is confirmed when the server or a retried check produced a
        terminal outcome for this correlation_id. Unconfirmed entries mean the
        SDK could not obtain an authoritative result and ``allowed`` must not
        be treated as a denial.
        """
        return self._confirmed

    @confirmed.setter
    def confirmed(self, confirmed: bool) -> None:
        """
        Set whether the response is authoritative
        """
        self._confirmed = confirmed

    @property
    def response(self) -> Any | None:
        """
        Return the underlying server response for this check, if any
        """
        return self._response

    @response.setter
    def response(self, response: Any | None) -> None:
        """
        Set the underlying server response for this check
        """
        self._response = response
