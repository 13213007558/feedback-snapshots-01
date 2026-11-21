# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from typing import Any, Dict, Optional, Union

from opensearchpy.helpers.signer import AWSV4Signer


class AWSV4SignerAsyncAuth:
    """
    AWS V4 Request Signer for Async Requests.

    :arg reuse_credentials_on_retry: when ``True`` (default) retries of a
        request reuse the frozen credentials resolved for its first attempt;
        when ``False`` every retry fetches a fresh snapshot from the
        credential provider.
    """

    def __init__(
        self,
        credentials: Any,
        region: str,
        service: str = "es",
        reuse_credentials_on_retry: bool = True,
    ) -> None:
        self.signer = AWSV4Signer(
            credentials,
            region,
            service,
            reuse_credentials_on_retry=reuse_credentials_on_retry,
        )

    def __call__(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        return self._sign_request(method=method, url=url, body=body, headers=headers)

    def reset_request(self) -> None:
        """Reset retry bookkeeping for the next logical request."""
        self.signer.reset_request()

    def _sign_request(
        self,
        method: str,
        url: str,
        body: Optional[Union[str, bytes]],
        headers: Optional[Dict[str, str]],
    ) -> Dict[str, str]:
        """
        This method helps in signing the request by injecting the required headers.
        :param prepared_request: unsigned headers
        :return: signed headers
        """

        updated_headers = self.signer.sign(
            method=method,
            url=url,
            body=body,
            headers=headers,
        )
        return updated_headers
