# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
import base64
import datetime
import json
import math
import weakref
from collections import namedtuple

import botocore
import botocore.auth
from botocore.awsrequest import create_request_object, prepare_request_dict
from botocore.compat import OrderedDict, get_current_datetime, total_seconds
from botocore.exceptions import (
    ParamValidationError,
    PresignExpirationError,
    UnknownClientMethodError,
    UnknownSignatureVersionError,
    UnsupportedSignatureVersionError,
)
from botocore.tokens import FrozenAuthToken
from botocore.utils import (
    ArnParser,
    datetime2timestamp,
    fix_s3_host,  # noqa: F401
)

# An immutable snapshot of the identity that signs a presigned request. The
# credential values, account ID, and expiration come from the same credential
# set so that endpoint selection and signing cannot observe different
# identities if the underlying provider refreshes mid-request.
SigningIdentity = namedtuple(
    'SigningIdentity',
    ['credentials', 'expires_at', 'access_key', 'account_id'],
)


def _snapshot_signing_identity(credentials):
    """Capture a single, consistent view of the credentials used to sign."""
    if credentials is None:
        return SigningIdentity(None, None, None, None)
    getter = getattr(credentials, 'get_frozen_credentials_with_expiry', None)
    if getter is not None:
        frozen, expires_at = getter()
    else:
        frozen_getter = getattr(credentials, 'get_frozen_credentials', None)
        if frozen_getter is not None:
            frozen = frozen_getter()
        else:
            frozen = credentials
        expires_at = None
    if frozen is None:
        return SigningIdentity(None, expires_at, None, None)
    return SigningIdentity(
        frozen,
        expires_at,
        getattr(frozen, 'access_key', None),
        getattr(frozen, 'account_id', None),
    )


def _remaining_seconds(expires_at, now=None):
    if now is None:
        now = get_current_datetime(remove_tzinfo=False)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    return total_seconds(expires_at - now)


def _presign_expiration_metadata(
    effective_expires_in,
    requested_expires_in,
    identity,
    now,
    signed_access_key,
):
    """Describe the validity window that was actually granted."""
    return {
        'requested_expires_in': requested_expires_in,
        'effective_expires_in': effective_expires_in,
        'expires_at': now + datetime.timedelta(seconds=effective_expires_in),
        'credential_expires_at': (
            identity.expires_at if identity is not None else None
        ),
        'access_key': signed_access_key,
    }


def _normalize_operation_name(name):
    if not isinstance(name, str):
        return name
    return botocore.xform_name(name, '-')


def _get_presign_expiration_config(client):
    s3_config = getattr(client.meta.config, 's3', None) or {}
    return s3_config.get('presign_expiration') or {}


def _get_operation_expires_cap(presign_expiration, operation_names):
    """Return the smallest configured maximum for the given operations."""
    maxima = presign_expiration.get('max_expires_in') or {}
    normalized = {}
    global_cap = None
    for operation, value in maxima.items():
        if operation == '*':
            global_cap = value
        else:
            normalized[_normalize_operation_name(operation)] = value
    caps = []
    if global_cap is not None:
        caps.append(global_cap)
    for operation in operation_names:
        cap = normalized.get(_normalize_operation_name(operation))
        if cap is not None:
            caps.append(cap)
    if not caps:
        return None
    return min(caps)


def _compute_effective_expires_in(
    requested_expires_in, operation_cap, identity, now
):
    """Compute the validity window a presigned request can actually honor.

    The window is the smallest of the requested value, any operation-specific
    maximum, and the remaining lifetime of the signing identity.
    """
    limits = [requested_expires_in]
    if operation_cap is not None:
        limits.append(operation_cap)
    if identity is not None and identity.expires_at is not None:
        limits.append(math.floor(_remaining_seconds(identity.expires_at, now)))
    return int(min(limits))


def _enforce_presign_expiration(
    effective_expires_in,
    requested_expires_in,
    presign_expiration,
    presign_type,
    identity,
):
    if effective_expires_in < 1:
        raise PresignExpirationError(
            presign_type=presign_type,
            requested_expires_in=requested_expires_in,
            reason=(
                'the effective validity window is zero. The signing '
                'credentials expire at '
                f'{identity.expires_at if identity is not None else None}'
            ),
        )
    if not presign_expiration.get('strict', False):
        return
    minimum = presign_expiration.get('minimum_expires_in', 1)
    if effective_expires_in < minimum:
        raise PresignExpirationError(
            presign_type=presign_type,
            requested_expires_in=requested_expires_in,
            reason=(
                f'the effective validity window is {effective_expires_in} '
                f'seconds, which is below the configured minimum of '
                f'{minimum} seconds'
            ),
        )


class _FrozenSigningCredentials:
    """Credentials that never refresh, used to sign a presigned request.

    Signing with the same snapshot that endpoint resolution used prevents a
    credential refresh from swapping the identity between those two steps.
    """

    def __init__(self, identity):
        self._identity = identity

    def get_frozen_credentials(self):
        return self._identity.credentials


def _resolve_presign_identity(client, context):
    """Snapshot the credentials used to sign, avoiding unsigned lookups."""
    signature_version = (
        context.get('auth_type') or client._request_signer.signature_version
    )
    if signature_version is botocore.UNSIGNED:
        return SigningIdentity(None, None, None, None)
    return _snapshot_signing_identity(client._request_signer._credentials)


def _presign_url(
    client,
    ClientMethod,
    Params,
    ExpiresIn,
    HttpMethod,
    return_metadata,
):
    client_method = ClientMethod
    params = Params
    if params is None:
        params = {}
    expires_in = ExpiresIn
    http_method = HttpMethod
    context = {
        'is_presign_request': True,
        'use_global_endpoint': _should_use_global_endpoint(client),
    }

    request_signer = client._request_signer

    try:
        operation_name = client._PY_TO_OP_NAME[client_method]
    except KeyError:
        raise UnknownClientMethodError(method_name=client_method)

    presign_expiration = _get_presign_expiration_config(client)
    identity = _resolve_presign_identity(client, context)
    context['signing_identity'] = identity
    now = get_current_datetime(remove_tzinfo=False)
    operation_cap = _get_operation_expires_cap(
        presign_expiration, [client_method, operation_name]
    )
    effective_expires_in = _compute_effective_expires_in(
        expires_in, operation_cap, identity, now
    )
    _enforce_presign_expiration(
        effective_expires_in,
        expires_in,
        presign_expiration,
        'url',
        identity,
    )

    operation_model = client.meta.service_model.operation_model(operation_name)
    params = client._emit_api_params(
        api_params=params,
        operation_model=operation_model,
        context=context,
    )
    bucket_is_arn = ArnParser.is_arn(params.get('Bucket', ''))
    (
        endpoint_url,
        additional_headers,
        properties,
    ) = client._resolve_endpoint_ruleset(
        operation_model,
        params,
        context,
        ignore_signing_region=(not bucket_is_arn),
    )

    request_dict = client._convert_to_request_dict(
        api_params=params,
        operation_model=operation_model,
        endpoint_url=endpoint_url,
        context=context,
        headers=additional_headers,
        set_user_agent_header=False,
    )

    if http_method is not None:
        request_dict['method'] = http_method

    if identity.credentials is None:
        url = request_signer.generate_presigned_url(
            request_dict=request_dict,
            expires_in=effective_expires_in,
            operation_name=operation_name,
        )
    else:
        url = request_signer.generate_presigned_url(
            request_dict=request_dict,
            expires_in=effective_expires_in,
            operation_name=operation_name,
            signing_identity=identity,
        )
    if not return_metadata:
        return url
    return {
        'url': url,
        'expiration': _presign_expiration_metadata(
            effective_expires_in,
            expires_in,
            identity,
            now,
            context.get('signing_access_key', identity.access_key),
        ),
    }


def _presign_post(
    client,
    Bucket,
    Key,
    Fields,
    Conditions,
    ExpiresIn,
    return_metadata,
):
    bucket = Bucket
    key = Key
    fields = Fields
    conditions = Conditions
    expires_in = ExpiresIn

    if fields is None:
        fields = {}
    else:
        fields = fields.copy()

    if conditions is None:
        conditions = []
    else:
        conditions = conditions.copy()

    context = {
        'is_presign_request': True,
        'use_global_endpoint': _should_use_global_endpoint(client),
    }

    presign_expiration = _get_presign_expiration_config(client)
    identity = _resolve_presign_identity(client, context)
    context['signing_identity'] = identity
    now = get_current_datetime(remove_tzinfo=False)
    operation_cap = _get_operation_expires_cap(
        presign_expiration, ['put_object', 'PutObject']
    )
    effective_expires_in = _compute_effective_expires_in(
        expires_in, operation_cap, identity, now
    )
    _enforce_presign_expiration(
        effective_expires_in,
        expires_in,
        presign_expiration,
        'post',
        identity,
    )

    post_presigner = S3PostPresigner(client._request_signer)

    # We choose the CreateBucket operation model because its url gets
    # serialized to what a presign post requires.
    operation_model = client.meta.service_model.operation_model('CreateBucket')
    params = client._emit_api_params(
        api_params={'Bucket': bucket},
        operation_model=operation_model,
        context=context,
    )
    bucket_is_arn = ArnParser.is_arn(params.get('Bucket', ''))
    (
        endpoint_url,
        additional_headers,
        properties,
    ) = client._resolve_endpoint_ruleset(
        operation_model,
        params,
        context,
        ignore_signing_region=(not bucket_is_arn),
    )

    request_dict = client._convert_to_request_dict(
        api_params=params,
        operation_model=operation_model,
        endpoint_url=endpoint_url,
        context=context,
        headers=additional_headers,
        set_user_agent_header=False,
    )

    # Append that the bucket name to the list of conditions.
    conditions.append({'bucket': bucket})

    # If the key ends with filename, the only constraint that can be
    # imposed is if it starts with the specified prefix.
    if key.endswith('${filename}'):
        conditions.append(["starts-with", '$key', key[: -len('${filename}')]])
    else:
        conditions.append({'key': key})

    # Add the key to the fields.
    fields['key'] = key

    if identity.credentials is None:
        result = post_presigner.generate_presigned_post(
            request_dict=request_dict,
            fields=fields,
            conditions=conditions,
            expires_in=effective_expires_in,
            now=now,
        )
    else:
        result = post_presigner.generate_presigned_post(
            request_dict=request_dict,
            fields=fields,
            conditions=conditions,
            expires_in=effective_expires_in,
            signing_identity=identity,
            now=now,
        )
    if not return_metadata:
        return result
    result['expiration'] = _presign_expiration_metadata(
        effective_expires_in,
        expires_in,
        identity,
        now,
        context.get('signing_access_key', identity.access_key),
    )
    return result


class RequestSigner:
    """
    An object to sign requests before they go out over the wire using
    one of the authentication mechanisms defined in ``auth.py``. This
    class fires two events scoped to a service and operation name:

    * choose-signer: Allows overriding the auth signer name.
    * before-sign: Allows mutating the request before signing.

    Together these events allow for customization of the request
    signing pipeline, including overrides, request path manipulation,
    and disabling signing per operation.


    :type service_id: botocore.model.ServiceId
    :param service_id: The service id for the service, e.g. ``S3``

    :type region_name: string
    :param region_name: Name of the service region, e.g. ``us-east-1``

    :type signing_name: string
    :param signing_name: Service signing name. This is usually the
                         same as the service name, but can differ. E.g.
                         ``emr`` vs. ``elasticmapreduce``.

    :type signature_version: string
    :param signature_version: Signature name like ``v4``.

    :type credentials: :py:class:`~botocore.credentials.Credentials`
    :param credentials: User credentials with which to sign requests.

    :type event_emitter: :py:class:`~botocore.hooks.BaseEventHooks`
    :param event_emitter: Extension mechanism to fire events.
    """

    def __init__(
        self,
        service_id,
        region_name,
        signing_name,
        signature_version,
        credentials,
        event_emitter,
        auth_token=None,
    ):
        self._region_name = region_name
        self._signing_name = signing_name
        self._signature_version = signature_version
        self._credentials = credentials
        self._auth_token = auth_token
        self._service_id = service_id

        # We need weakref to prevent leaking memory in Python 2.6 on Linux 2.6
        self._event_emitter = weakref.proxy(event_emitter)

    @property
    def region_name(self):
        return self._region_name

    @property
    def signature_version(self):
        return self._signature_version

    @property
    def signing_name(self):
        return self._signing_name

    def handler(self, operation_name=None, request=None, **kwargs):
        # This is typically hooked up to the "request-created" event
        # from a client's event emitter.  When a new request is created
        # this method is invoked to sign the request.
        # Don't call this method directly.
        return self.sign(operation_name, request)

    def sign(
        self,
        operation_name,
        request,
        region_name=None,
        signing_type='standard',
        expires_in=None,
        signing_name=None,
        signing_identity=None,
    ):
        """Sign a request before it goes out over the wire.

        :type operation_name: string
        :param operation_name: The name of the current operation, e.g.
                               ``ListBuckets``.
        :type request: AWSRequest
        :param request: The request object to be sent over the wire.

        :type region_name: str
        :param region_name: The region to sign the request for.

        :type signing_type: str
        :param signing_type: The type of signing to perform. This can be one of
            three possible values:

            * 'standard'     - This should be used for most requests.
            * 'presign-url'  - This should be used when pre-signing a request.
            * 'presign-post' - This should be used when pre-signing an S3 post.

        :type expires_in: int
        :param expires_in: The number of seconds the presigned url is valid
            for. This parameter is only valid for signing type 'presign-url'.

        :type signing_name: str
        :param signing_name: The name to use for the service when signing.

        :type signing_identity: SigningIdentity
        :param signing_identity: An optional credential snapshot to sign with.
            Pre-signing uses this to keep endpoint selection and signing on
            the same identity.
        """
        explicit_region_name = region_name
        if region_name is None:
            region_name = self._region_name

        if signing_name is None:
            signing_name = self._signing_name

        signature_version = self._choose_signer(
            operation_name, signing_type, request.context
        )

        # Allow mutating request before signing
        self._event_emitter.emit(
            f'before-sign.{self._service_id.hyphenize()}.{operation_name}',
            request=request,
            signing_name=signing_name,
            region_name=self._region_name,
            signature_version=signature_version,
            request_signer=self,
            operation_name=operation_name,
        )

        if signature_version != botocore.UNSIGNED:
            kwargs = {
                'signing_name': signing_name,
                'region_name': region_name,
                'signature_version': signature_version,
            }
            if expires_in is not None:
                kwargs['expires'] = expires_in
            signing_context = request.context.get('signing', {})
            if not explicit_region_name and signing_context.get('region'):
                kwargs['region_name'] = signing_context['region']
            if signing_context.get('signing_name'):
                kwargs['signing_name'] = signing_context['signing_name']
            if signing_context.get('request_credentials'):
                kwargs['request_credentials'] = signing_context[
                    'request_credentials'
                ]
            if signing_context.get('identity_cache') is not None:
                self._resolve_identity_cache(
                    kwargs,
                    signing_context['identity_cache'],
                    signing_context['cache_key'],
                )
            elif signing_identity is not None:
                # Sign with the identity snapshot captured while resolving
                # the endpoint instead of reading the provider again, which
                # could have refreshed to a different identity.
                kwargs['request_credentials'] = _FrozenSigningCredentials(
                    signing_identity
                )
            try:
                auth = self.get_auth_instance(**kwargs)
            except UnknownSignatureVersionError as e:
                if signing_type != 'standard':
                    raise UnsupportedSignatureVersionError(
                        signature_version=signature_version
                    )
                else:
                    raise e

            auth.add_auth(request)
            if signing_type != 'standard':
                # Record the identity that actually signed a presigned
                # request so callers can reconcile it with the validity
                # window. Standard request signing leaves the shared request
                # context untouched.
                credentials = getattr(auth, 'credentials', None)
                access_key = getattr(credentials, 'access_key', None)
                if access_key is not None:
                    request.context['signing_access_key'] = access_key

    def _resolve_identity_cache(self, kwargs, cache, cache_key):
        kwargs['identity_cache'] = cache
        kwargs['cache_key'] = cache_key

    def _choose_signer(self, operation_name, signing_type, context):
        """
        Allow setting the signature version via the choose-signer event.
        A value of `botocore.UNSIGNED` means no signing will be performed.

        :param operation_name: The operation to sign.
        :param signing_type: The type of signing that the signer is to be used
            for.
        :return: The signature version to sign with.
        """
        signing_type_suffix_map = {
            'presign-post': '-presign-post',
            'presign-url': '-query',
        }
        suffix = signing_type_suffix_map.get(signing_type, '')

        # operation specific signing context takes precedent over client-level
        # defaults
        signature_version = context.get('auth_type') or self._signature_version
        signing = context.get('signing', {})
        signing_name = signing.get('signing_name', self._signing_name)
        region_name = signing.get('region', self._region_name)
        if (
            signature_version is not botocore.UNSIGNED
            and not signature_version.endswith(suffix)
        ):
            signature_version += suffix

        handler, response = self._event_emitter.emit_until_response(
            f'choose-signer.{self._service_id.hyphenize()}.{operation_name}',
            signing_name=signing_name,
            region_name=region_name,
            signature_version=signature_version,
            context=context,
        )

        if response is not None:
            signature_version = response
            # The suffix needs to be checked again in case we get an improper
            # signature version from choose-signer.
            if (
                signature_version is not botocore.UNSIGNED
                and not signature_version.endswith(suffix)
            ):
                signature_version += suffix

        return signature_version

    def get_auth_instance(
        self,
        signing_name,
        region_name,
        signature_version=None,
        request_credentials=None,
        **kwargs,
    ):
        """
        Get an auth instance which can be used to sign a request
        using the given signature version.

        :type signing_name: string
        :param signing_name: Service signing name. This is usually the
                             same as the service name, but can differ. E.g.
                             ``emr`` vs. ``elasticmapreduce``.

        :type region_name: string
        :param region_name: Name of the service region, e.g. ``us-east-1``

        :type signature_version: string
        :param signature_version: Signature name like ``v4``.

        :rtype: :py:class:`~botocore.auth.BaseSigner`
        :return: Auth instance to sign a request.
        """
        if signature_version is None:
            signature_version = self._signature_version

        cls = botocore.auth.AUTH_TYPE_MAPS.get(signature_version)
        if cls is None:
            raise UnknownSignatureVersionError(
                signature_version=signature_version
            )

        if cls.REQUIRES_TOKEN is True:
            if self._auth_token and not isinstance(
                self._auth_token, FrozenAuthToken
            ):
                frozen_token = self._auth_token.get_frozen_token()
            else:
                frozen_token = self._auth_token
            auth = cls(frozen_token)
            return auth

        credentials = request_credentials or self._credentials
        if getattr(cls, "REQUIRES_IDENTITY_CACHE", None) is True:
            cache = kwargs["identity_cache"]
            key = kwargs["cache_key"]
            credentials = cache.get_credentials(key)
            del kwargs["cache_key"]

        # If there's no credentials provided (i.e credentials is None),
        # then we'll pass a value of "None" over to the auth classes,
        # which already handle the cases where no credentials have
        # been provided.
        frozen_credentials = None
        if credentials is not None:
            frozen_credentials = credentials.get_frozen_credentials()
        kwargs['credentials'] = frozen_credentials
        if cls.REQUIRES_REGION:
            if self._region_name is None:
                raise botocore.exceptions.NoRegionError()
            kwargs['region_name'] = region_name
            kwargs['service_name'] = signing_name
        auth = cls(**kwargs)
        return auth

    # Alias get_auth for backwards compatibility.
    get_auth = get_auth_instance

    def generate_presigned_url(
        self,
        request_dict,
        operation_name,
        expires_in=3600,
        region_name=None,
        signing_name=None,
        signing_identity=None,
    ):
        """Generates a presigned url

        :type request_dict: dict
        :param request_dict: The prepared request dictionary returned by
            ``botocore.awsrequest.prepare_request_dict()``

        :type operation_name: str
        :param operation_name: The operation being signed.

        :type expires_in: int
        :param expires_in: The number of seconds the presigned url is valid
            for. By default it expires in an hour (3600 seconds)

        :type region_name: string
        :param region_name: The region name to sign the presigned url.

        :type signing_name: str
        :param signing_name: The name to use for the service when signing.

        :type signing_identity: SigningIdentity
        :param signing_identity: An optional credential snapshot captured
            before endpoint selection. When provided, the URL is signed with
            this identity so it matches the endpoint that was resolved.

        :returns: The presigned url
        """
        request = create_request_object(request_dict)
        self.sign(
            operation_name,
            request,
            region_name,
            'presign-url',
            expires_in,
            signing_name,
            signing_identity=signing_identity,
        )

        request.prepare()
        return request.url


class CloudFrontSigner:
    '''A signer to create a signed CloudFront URL.

    First you create a cloudfront signer based on a normalized RSA signer::

        import rsa
        def rsa_signer(message):
            private_key = open('private_key.pem', 'r').read()
            return rsa.sign(
                message,
                rsa.PrivateKey.load_pkcs1(private_key.encode('utf8')),
                'SHA-1')  # CloudFront requires SHA-1 hash
        cf_signer = CloudFrontSigner(key_id, rsa_signer)

    To sign with a canned policy::

        signed_url = cf_signer.generate_signed_url(
            url, date_less_than=datetime(2015, 12, 1))

    To sign with a custom policy::

        signed_url = cf_signer.generate_signed_url(url, policy=my_policy)
    '''

    def __init__(self, key_id, rsa_signer):
        """Create a CloudFrontSigner.

        :type key_id: str
        :param key_id: The CloudFront Key Pair ID

        :type rsa_signer: callable
        :param rsa_signer: An RSA signer.
               Its only input parameter will be the message to be signed,
               and its output will be the signed content as a binary string.
               The hash algorithm needed by CloudFront is SHA-1.
        """
        self.key_id = key_id
        self.rsa_signer = rsa_signer

    def generate_presigned_url(self, url, date_less_than=None, policy=None):
        """Creates a signed CloudFront URL based on given parameters.

        :type url: str
        :param url: The URL of the protected object

        :type date_less_than: datetime
        :param date_less_than: The URL will expire after that date and time

        :type policy: str
        :param policy: The custom policy, possibly built by self.build_policy()

        :rtype: str
        :return: The signed URL.
        """
        both_args_supplied = date_less_than is not None and policy is not None
        neither_arg_supplied = date_less_than is None and policy is None
        if both_args_supplied or neither_arg_supplied:
            e = 'Need to provide either date_less_than or policy, but not both'
            raise ValueError(e)
        if date_less_than is not None:
            # We still need to build a canned policy for signing purpose
            policy = self.build_policy(url, date_less_than)
        if isinstance(policy, str):
            policy = policy.encode('utf8')
        if date_less_than is not None:
            params = [f'Expires={int(datetime2timestamp(date_less_than))}']
        else:
            params = [f"Policy={self._url_b64encode(policy).decode('utf8')}"]
        signature = self.rsa_signer(policy)
        params.extend(
            [
                f"Signature={self._url_b64encode(signature).decode('utf8')}",
                f"Key-Pair-Id={self.key_id}",
            ]
        )
        return self._build_url(url, params)

    def _build_url(self, base_url, extra_params):
        separator = '&' if '?' in base_url else '?'
        return base_url + separator + '&'.join(extra_params)

    def build_policy(
        self, resource, date_less_than, date_greater_than=None, ip_address=None
    ):
        """A helper to build policy.

        :type resource: str
        :param resource: The URL or the stream filename of the protected object

        :type date_less_than: datetime
        :param date_less_than: The URL will expire after the time has passed

        :type date_greater_than: datetime
        :param date_greater_than: The URL will not be valid until this time

        :type ip_address: str
        :param ip_address: Use 'x.x.x.x' for an IP, or 'x.x.x.x/x' for a subnet

        :rtype: str
        :return: The policy in a compact string.
        """
        # Note:
        # 1. Order in canned policy is significant. Special care has been taken
        #    to ensure the output will match the order defined by the document.
        #    There is also a test case to ensure that order.
        #    SEE: http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-canned-policy.html#private-content-canned-policy-creating-policy-statement
        # 2. Albeit the order in custom policy is not required by CloudFront,
        #    we still use OrderedDict internally to ensure the result is stable
        #    and also matches canned policy requirement.
        #    SEE: http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html
        moment = int(datetime2timestamp(date_less_than))
        condition = OrderedDict({"DateLessThan": {"AWS:EpochTime": moment}})
        if ip_address:
            if '/' not in ip_address:
                ip_address += '/32'
            condition["IpAddress"] = {"AWS:SourceIp": ip_address}
        if date_greater_than:
            moment = int(datetime2timestamp(date_greater_than))
            condition["DateGreaterThan"] = {"AWS:EpochTime": moment}
        ordered_payload = [('Resource', resource), ('Condition', condition)]
        custom_policy = {"Statement": [OrderedDict(ordered_payload)]}
        return json.dumps(custom_policy, separators=(',', ':'))

    def _url_b64encode(self, data):
        # Required by CloudFront. See also:
        # http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-linux-openssl.html
        return (
            base64.b64encode(data)
            .replace(b'+', b'-')
            .replace(b'=', b'_')
            .replace(b'/', b'~')
        )


def add_generate_db_auth_token(class_attributes, **kwargs):
    class_attributes['generate_db_auth_token'] = generate_db_auth_token


def add_dsql_generate_db_auth_token_methods(class_attributes, **kwargs):
    class_attributes['generate_db_connect_auth_token'] = (
        dsql_generate_db_connect_auth_token
    )
    class_attributes['generate_db_connect_admin_auth_token'] = (
        dsql_generate_db_connect_admin_auth_token
    )


def generate_db_auth_token(self, DBHostname, Port, DBUsername, Region=None):
    """Generates an auth token used to connect to a db with IAM credentials.

    :type DBHostname: str
    :param DBHostname: The hostname of the database to connect to.

    :type Port: int
    :param Port: The port number the database is listening on.

    :type DBUsername: str
    :param DBUsername: The username to log in as.

    :type Region: str
    :param Region: The region the database is in. If None, the client
        region will be used.

    :return: A presigned url which can be used as an auth token.
    """
    region = Region
    if region is None:
        region = self.meta.region_name

    params = {
        'Action': 'connect',
        'DBUser': DBUsername,
    }

    request_dict = {
        'url_path': '/',
        'query_string': '',
        'headers': {},
        'body': params,
        'method': 'GET',
    }

    # RDS requires that the scheme not be set when sent over. This can cause
    # issues when signing because the Python url parsing libraries follow
    # RFC 1808 closely, which states that a netloc must be introduced by `//`.
    # Otherwise the url is presumed to be relative, and thus the whole
    # netloc would be treated as a path component. To work around this we
    # introduce https here and remove it once we're done processing it.
    scheme = 'https://'
    endpoint_url = f'{scheme}{DBHostname}:{Port}'
    prepare_request_dict(request_dict, endpoint_url)
    presigned_url = self._request_signer.generate_presigned_url(
        operation_name='connect',
        request_dict=request_dict,
        region_name=region,
        expires_in=900,
        signing_name='rds-db',
    )
    return presigned_url[len(scheme) :]


def _dsql_generate_db_auth_token(
    self, Hostname, Action, Region=None, ExpiresIn=900
):
    """Generate a DSQL database token for an arbitrary action.

    :type Hostname: str
    :param Hostname: The DSQL endpoint host name.

    :type Action: str
    :param Action: Action to perform on the cluster (DbConnectAdmin or DbConnect).

    :type Region: str
    :param Region: The AWS region where the DSQL Cluster is hosted. If None, the client region will be used.

    :type ExpiresIn: int
    :param ExpiresIn: The token expiry duration in seconds (default is 900 seconds).

    :return: A presigned url which can be used as an auth token.
    """
    possible_actions = ("DbConnect", "DbConnectAdmin")

    if Action not in possible_actions:
        raise ParamValidationError(
            report=f"Received {Action} for action but expected one of: {', '.join(possible_actions)}"
        )

    if Region is None:
        Region = self.meta.region_name

    request_dict = {
        'url_path': '/',
        'query_string': '',
        'headers': {},
        'body': {
            'Action': Action,
        },
        'method': 'GET',
    }
    scheme = 'https://'
    endpoint_url = f'{scheme}{Hostname}'
    prepare_request_dict(request_dict, endpoint_url)
    presigned_url = self._request_signer.generate_presigned_url(
        operation_name=Action,
        request_dict=request_dict,
        region_name=Region,
        expires_in=ExpiresIn,
        signing_name='dsql',
    )
    return presigned_url[len(scheme) :]


def dsql_generate_db_connect_auth_token(
    self, Hostname, Region=None, ExpiresIn=900
):
    """Generate a DSQL database token for the "DbConnect" action.

    :type Hostname: str
    :param Hostname: The DSQL endpoint host name.

    :type Region: str
    :param Region: The AWS region where the DSQL Cluster is hosted. If None, the client region will be used.

    :type ExpiresIn: int
    :param ExpiresIn: The token expiry duration in seconds (default is 900 seconds).

    :return: A presigned url which can be used as an auth token.
    """
    return _dsql_generate_db_auth_token(
        self, Hostname, "DbConnect", Region, ExpiresIn
    )


def dsql_generate_db_connect_admin_auth_token(
    self, Hostname, Region=None, ExpiresIn=900
):
    """Generate a DSQL database token for the "DbConnectAdmin" action.

    :type Hostname: str
    :param Hostname: The DSQL endpoint host name.

    :type Region: str
    :param Region: The AWS region where the DSQL Cluster is hosted. If None, the client region will be used.

    :type ExpiresIn: int
    :param ExpiresIn: The token expiry duration in seconds (default is 900 seconds).

    :return: A presigned url which can be used as an auth token.
    """
    return _dsql_generate_db_auth_token(
        self, Hostname, "DbConnectAdmin", Region, ExpiresIn
    )


class S3PostPresigner:
    def __init__(self, request_signer):
        self._request_signer = request_signer

    def generate_presigned_post(
        self,
        request_dict,
        fields=None,
        conditions=None,
        expires_in=3600,
        region_name=None,
        signing_identity=None,
        now=None,
    ):
        """Generates the url and the form fields used for a presigned s3 post

        :type request_dict: dict
        :param request_dict: The prepared request dictionary returned by
            ``botocore.awsrequest.prepare_request_dict()``

        :type fields: dict
        :param fields: A dictionary of prefilled form fields to build on top
            of.

        :type conditions: list
        :param conditions: A list of conditions to include in the policy. Each
            element can be either a list or a structure. For example:

            .. code:: python

                [
                    {"acl": "public-read"},
                    {"bucket": "amzn-s3-demo-bucket"},
                    ["starts-with", "$key", "mykey"]
                ]

        :type expires_in: int
        :param expires_in: The number of seconds the presigned post is valid
            for.

        :type region_name: string
        :param region_name: The region name to sign the presigned post to.

        :type signing_identity: SigningIdentity
        :param signing_identity: An optional credential snapshot captured
            before endpoint selection. When provided, the form is signed with
            this identity so it matches the endpoint that was resolved.

        :type now: datetime
        :param now: The moment the validity window is measured from. Pre-sign
            callers pass the same value used to compute ``expires_in`` so the
            policy expiration and the reported window agree.

        :rtype: dict
        :returns: A dictionary with two elements: ``url`` and ``fields``.
            Url is the url to post to. Fields is a dictionary filled with
            the form fields and respective values to use when submitting the
            post. For example:

            .. code:: python

                {
                    'url': 'https://amzn-s3-demo-bucket.s3.amazonaws.com',
                    'fields': {
                        'acl': 'public-read',
                        'key': 'mykey',
                        'signature': 'mysignature',
                        'policy': 'mybase64 encoded policy'
                    }
                }
        """
        if fields is None:
            fields = {}

        if conditions is None:
            conditions = []

        # Create the policy for the post.
        policy = {}

        # Create an expiration date for the policy
        datetime_now = now if now is not None else get_current_datetime()
        expire_date = datetime_now + datetime.timedelta(seconds=expires_in)
        policy['expiration'] = expire_date.strftime(botocore.auth.ISO8601)

        # Append all of the conditions that the user supplied.
        policy['conditions'] = []
        for condition in conditions:
            policy['conditions'].append(condition)

        # Store the policy and the fields in the request for signing
        request = create_request_object(request_dict)
        request.context['s3-presign-post-fields'] = fields
        request.context['s3-presign-post-policy'] = policy

        self._request_signer.sign(
            'PutObject',
            request,
            region_name,
            'presign-post',
            signing_identity=signing_identity,
        )
        # Return the url and the fields for th form to post.
        return {'url': request.url, 'fields': fields}


def add_generate_presigned_url(class_attributes, **kwargs):
    class_attributes['generate_presigned_url'] = generate_presigned_url


def generate_presigned_url(
    self, ClientMethod, Params=None, ExpiresIn=3600, HttpMethod=None
):
    """Generate a presigned url given a client, its method, and arguments

    .. warning::

        For backwards compatibility, S3 presigned URLs use Signature
        Version 2 by default in regions where S3 supports it. As a result,
        some ``Params`` entries are not signed. Some headers, including the
        conditionals and ``Range``, are also silently dropped.

        It is recommended to configure the S3 client with Signature
        Version 4 by setting ``signature_version='s3v4'`` in the client's
        ``Config``.

    :type ClientMethod: string
    :param ClientMethod: The client method to presign for

    :type Params: dict
    :param Params: The parameters normally passed to
        ``ClientMethod``.

    :type ExpiresIn: int
    :param ExpiresIn: The number of seconds the presigned url is valid
        for. By default it expires in an hour (3600 seconds)

    :type HttpMethod: string
    :param HttpMethod: The http method to use on the generated url. By
        default, the http method is whatever is used in the method's model.

    :returns: The presigned url

    The effective validity window is the smallest of ``ExpiresIn``, any
    ``presign_expiration.max_expires_in`` configured for the operation, and
    the remaining lifetime of the credentials used to sign. When
    ``presign_expiration.strict`` is enabled, a window shorter than
    ``presign_expiration.minimum_expires_in`` raises
    :class:`~botocore.exceptions.PresignExpirationError` instead of issuing a
    URL that appears valid for longer.

    The returned value remains a URL string. To inspect the window that was
    actually granted, or the identity that signed it, use
    :meth:`~botocore.client.BaseClient.generate_presigned_url_with_metadata`.
    """
    return _presign_url(
        self, ClientMethod, Params, ExpiresIn, HttpMethod, False
    )


def add_generate_presigned_url_with_metadata(class_attributes, **kwargs):
    class_attributes['generate_presigned_url_with_metadata'] = (
        generate_presigned_url_with_metadata
    )


def generate_presigned_url_with_metadata(
    self, ClientMethod, Params=None, ExpiresIn=3600, HttpMethod=None
):
    """Generate a presigned url and report the window it actually grants

    This takes the same arguments as ``generate_presigned_url``. The return
    value is a dictionary with ``url`` and ``expiration`` keys. The
    ``expiration`` entry describes the effective validity window and the
    identity that signed the URL so callers can record or reconcile it.

    ``generate_presigned_url`` is unchanged and still returns only the URL
    string.
    """
    return _presign_url(
        self, ClientMethod, Params, ExpiresIn, HttpMethod, True
    )


def add_generate_presigned_post(class_attributes, **kwargs):
    class_attributes['generate_presigned_post'] = generate_presigned_post


def generate_presigned_post(
    self, Bucket, Key, Fields=None, Conditions=None, ExpiresIn=3600
):
    """Builds the url and the form fields used for a presigned s3 post

    :type Bucket: string
    :param Bucket: The name of the bucket to presign the post to. Note that
        bucket related conditions should not be included in the
        ``conditions`` parameter.

    :type Key: string
    :param Key: Key name, optionally add ${filename} to the end to
        attach the submitted filename. Note that key related conditions and
        fields are filled out for you and should not be included in the
        ``Fields`` or ``Conditions`` parameter.

    :type Fields: dict
    :param Fields: A dictionary of prefilled form fields to build on top
        of. Elements that may be included are acl, Cache-Control,
        Content-Type, Content-Disposition, Content-Encoding, Expires,
        success_action_redirect, redirect, success_action_status,
        and x-amz-meta-.

        Note that if a particular element is included in the fields
        dictionary it will not be automatically added to the conditions
        list. You must specify a condition for the element as well.

    :type Conditions: list
    :param Conditions: A list of conditions to include in the policy. Each
        element can be either a list or a structure. For example:

        .. code:: python

            [
                {"acl": "public-read"},
                ["content-length-range", 2, 5],
                ["starts-with", "$success_action_redirect", ""]
            ]

        Conditions that are included may pertain to acl,
        content-length-range, Cache-Control, Content-Type,
        Content-Disposition, Content-Encoding, Expires,
        success_action_redirect, redirect, success_action_status,
        and/or x-amz-meta-.

        Note that if you include a condition, you must specify
        a valid value in the fields dictionary as well. A value will
        not be added automatically to the fields dictionary based on the
        conditions.

    :type ExpiresIn: int
    :param ExpiresIn: The number of seconds the presigned post
        is valid for.

    :rtype: dict
    :returns: A dictionary with two elements: ``url`` and ``fields``.
        Url is the url to post to. Fields is a dictionary filled with
        the form fields and respective values to use when submitting the
        post. For example:

        .. code:: python

            {
                'url': 'https://amzn-s3-demo-bucket.s3.amazonaws.com',
                'fields': {
                    'acl': 'public-read',
                    'key': 'mykey',
                    'signature': 'mysignature',
                    'policy': 'mybase64 encoded policy'
                }
            }

    The effective validity window is the smallest of ``ExpiresIn``, any
    ``presign_expiration.max_expires_in`` configured for the operation, and
    the remaining lifetime of the credentials used to sign. When
    ``presign_expiration.strict`` is enabled, a window shorter than
    ``presign_expiration.minimum_expires_in`` raises
    :class:`~botocore.exceptions.PresignExpirationError` instead of issuing a
    form that appears valid for longer.

    To inspect the window that was actually granted, or the identity that
    signed it, use
    :meth:`~botocore.client.BaseClient.generate_presigned_post_with_metadata`.
    """
    return _presign_post(
        self, Bucket, Key, Fields, Conditions, ExpiresIn, False
    )


def add_generate_presigned_post_with_metadata(class_attributes, **kwargs):
    class_attributes['generate_presigned_post_with_metadata'] = (
        generate_presigned_post_with_metadata
    )


def generate_presigned_post_with_metadata(
    self, Bucket, Key, Fields=None, Conditions=None, ExpiresIn=3600
):
    """Build a presigned post and report the window it actually grants

    This takes the same arguments as ``generate_presigned_post``. The return
    value is a dictionary with ``url``, ``fields``, and ``expiration`` keys.
    ``url`` and ``fields`` have the same shape as ``generate_presigned_post``.
    ``expiration`` describes the effective validity window and the identity
    that signed the form.

    ``generate_presigned_post`` is unchanged and still returns only ``url``
    and ``fields``.
    """
    return _presign_post(
        self, Bucket, Key, Fields, Conditions, ExpiresIn, True
    )


def _should_use_global_endpoint(client):
    if client.meta.partition != 'aws':
        return False
    s3_config = client.meta.config.s3
    if s3_config:
        if s3_config.get('use_dualstack_endpoint', False):
            return False
        if (
            s3_config.get('us_east_1_regional_endpoint') == 'regional'
            and client.meta.config.region_name == 'us-east-1'
        ):
            return False
        if s3_config.get('addressing_style') == 'virtual':
            return False
    return True
