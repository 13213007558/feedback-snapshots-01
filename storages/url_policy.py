from django.core.exceptions import SuspiciousOperation


class SignedUrlParameterError(SuspiciousOperation):
    """A caller requested response metadata that the storage policy forbids.

    The offending parameter *names* may be shown to callers; never include the
    parameter values or any storage credentials in the message.
    """


class SignedUrlParameterPolicy:
    """Allow-list and alias defaults for signed URL response metadata.

    Storage backends hand the parameters of ``Storage.url()`` straight to the
    underlying signing API (boto3's ``generate_presigned_url`` or Azure's
    ``generate_blob_sas``).  Without an allow-list a caller can override any
    response header the storage provider supports, which lets an untrusted
    caller change e.g. ``Content-Disposition`` of a link meant for inline
    preview into an attachment download (or inject arbitrary signing
    parameters).

    The policy speaks each backend's *native* parameter names, so S3's
    ``ResponseContentDisposition`` and Azure's ``content_disposition`` are
    configured independently.

    Parameters
    ----------
    allowed_parameters:
        Iterable of parameter names that callers are permitted to pass to
        ``url()``.  When empty (the default) every parameter is allowed,
        preserving the historical behavior.
    aliases:
        Mapping of alias name to a mapping of default parameters applied when
        ``url(..., alias=...)`` is used.  Explicit parameters passed by the
        caller take precedence over alias defaults.
    """

    def __init__(self, allowed_parameters=None, aliases=None):
        self.allowed_parameters = (
            frozenset(allowed_parameters) if allowed_parameters else frozenset()
        )
        self.aliases = dict(aliases or {})
        for alias_name, defaults in self.aliases.items():
            self._reject_disallowed(
                defaults, "alias {!r}".format(alias_name)
            )

    @property
    def enforced(self):
        return bool(self.allowed_parameters)

    def _reject_disallowed(self, parameters, context):
        if not self.enforced:
            return
        disallowed = sorted(
            key for key in parameters if key not in self.allowed_parameters
        )
        if disallowed:
            raise SignedUrlParameterError(
                "Signed URL parameter(s) {} are not permitted by the "
                "configured policy ({}).".format(
                    ", ".join(disallowed), context
                )
            )

    def resolve(self, parameters=None, alias=None):
        """Merge alias defaults with caller parameters and enforce the policy.

        Raises :class:`SignedUrlParameterError` before any signing API is
        touched when a parameter is missing from the allow-list.
        """
        if alias is not None and alias not in self.aliases:
            raise SignedUrlParameterError(
                "Unknown signed URL parameter alias {!r}.".format(alias)
            )

        resolved = {}
        if alias is not None:
            resolved.update(self.aliases[alias])
        if parameters:
            resolved.update(parameters)

        self._reject_disallowed(resolved, "url() call")
        return resolved
