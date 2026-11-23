# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Base class interface for crypto material managers."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CryptoMaterialsManager(object):
    """Parent interface for crypto material manager classes.

    .. versionadded:: 1.3.0
    """

    @abc.abstractmethod
    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

    @abc.abstractmethod
    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """

    def commit_encryption_materials_usage(self, materials, actual_plaintext_bytes=None):
        """Settles a materials reservation as a completed, billed message.

        Managers that do not reserve budget (everything except the caching CMM) have nothing
        to settle, so the default behavior is a no-op.

        :param materials: Encryption materials previously returned by this manager
        :type materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        :param int actual_plaintext_bytes: Bytes the stream really encrypted, when known.
            Used to reconcile an unknown-length reservation made against an upper bound.
        """

    def release_encryption_materials(self, materials):
        """Releases a materials reservation without billing it.

        Managers that do not reserve budget (everything except the caching CMM) have nothing
        to release, so the default behavior is a no-op.

        :param materials: Encryption materials previously returned by this manager
        :type materials: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """
