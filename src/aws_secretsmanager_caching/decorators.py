# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Decorators for use with caching library"""

import asyncio
import json
from functools import wraps


class InjectSecretString:
    """Decorator implementing high-level Secrets Manager caching client"""

    def __init__(self, secret_id, cache):
        """
        Constructs a decorator to inject a single non-keyworded argument from a cached secret for a given function.

        :type secret_id: str
        :param secret_id: The secret identifier

        :type cache: aws_secretsmanager_caching.SecretCache
        :param cache: Secret cache
        """

        self.cache = cache
        self.secret_id = secret_id

    def _build_args(self, func, args):
        """
        Resolve the positional arguments for a single wrapped invocation.

        The secret is fetched on demand and held only in a local for the lifetime
        of that invocation; it is never stored on the decorator or the wrapper.
        A fresh tuple is returned per call so concurrent invocations cannot share
        or mutate injected state.
        """
        secret = self.cache.get_secret_string(secret_id=self.secret_id)

        # Prevent clobbering self arg in class methods
        if args and hasattr(args[0].__class__, func.__name__):
            return (args[0], secret) + args[1:]
        return (secret,) + args

    def __call__(self, func):
        """
        Return a function with cached secret injected as first argument.

        Both synchronous functions and coroutine functions are supported. For
        coroutines the cache is only consulted once the returned coroutine is
        actually driven, so merely creating it neither fetches nor pins a
        secret; cancellation before execution never touches the cache.

        :type func: object
        :param func: The function for injecting a single non-keyworded argument too.
        :return The function with the injected argument.
        """
        if asyncio.iscoroutinefunction(func):

            # Using functools.wraps preserves the metadata of the wrapped function
            @wraps(func)
            async def _wrapped_coroutine(*args, **kwargs):
                """
                Internal coroutine to execute wrapped function
                """
                injected_args = self._build_args(func, args)
                return await func(*injected_args, **kwargs)

            return _wrapped_coroutine

        # Using functools.wraps preserves the metadata of the wrapped function
        @wraps(func)
        def _wrapped_func(*args, **kwargs):
            """
            Internal function to execute wrapped function
            """
            injected_args = self._build_args(func, args)
            return func(*injected_args, **kwargs)

        return _wrapped_func


class InjectKeywordedSecretString:
    """Decorator implementing high-level Secrets Manager caching client using JSON-based secrets"""

    def __init__(self, secret_id, cache, **kwargs):
        """
        Construct a decorator to inject a variable list of keyword arguments to a given function with resolved values
        from a cached secret.

        :type kwargs: dict
        :param kwargs: dictionary mapping original keyword argument of wrapped function to JSON-encoded secret key

        :type secret_id: str
        :param secret_id: The secret identifier

        :type cache: aws_secretsmanager_caching.SecretCache
        :param cache: Secret cache
        """

        self.cache = cache
        self.kwarg_map = kwargs
        self.secret_id = secret_id

    def _resolve_kwargs(self):
        """
        Resolve the keyword arguments for a single wrapped invocation.

        The secret string is fetched and parsed into a fresh dict local to this
        call. No resolved value is retained on the decorator or the wrapper,
        and raised errors reference only the missing key name, never the
        secret material itself.
        """
        try:
            secret = json.loads(
                self.cache.get_secret_string(secret_id=self.secret_id)
            )
        except json.decoder.JSONDecodeError:
            raise RuntimeError("Cached secret is not valid JSON") from None

        resolved_kwargs = {}
        for orig_kwarg, secret_key in self.kwarg_map.items():
            try:
                resolved_kwargs[orig_kwarg] = secret[secret_key]
            except KeyError:
                raise RuntimeError(
                    f"Cached secret does not contain key {secret_key}"
                ) from None
        return resolved_kwargs

    def __call__(self, func):
        """
        Return a function with injected keyword arguments from a cached secret.

        Both synchronous functions and coroutine functions are supported. For
        coroutines the cache is only consulted once the returned coroutine is
        actually driven, so merely creating it neither fetches nor pins a
        secret; cancellation before execution never touches the cache.

        :type func: object
        :param func: function for injecting keyword arguments.
        :return The original function with injected keyword arguments
        """
        if asyncio.iscoroutinefunction(func):

            @wraps(func)
            async def _wrapped_coroutine(*args, **kwargs):
                """
                Internal coroutine to execute wrapped function
                """
                resolved_kwargs = self._resolve_kwargs()
                return await func(*args, **resolved_kwargs, **kwargs)

            return _wrapped_coroutine

        @wraps(func)
        def _wrapped_func(*args, **kwargs):
            """
            Internal function to execute wrapped function
            """
            resolved_kwargs = self._resolve_kwargs()
            return func(*args, **resolved_kwargs, **kwargs)

        return _wrapped_func
