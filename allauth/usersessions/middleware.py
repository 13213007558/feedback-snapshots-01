from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

from allauth.usersessions.internal import usersessionkit


class UserSessionsMiddleware:
    def __init__(self, get_response) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        session = getattr(request, "session", None)
        if session is not None and usersessionkit.is_session_ended(session.session_key):
            # This session was ended, possibly while a slow request was still in
            # flight. Ending takes precedence: drop the resurrected session so
            # that the request cannot be (re)authenticated nor bring the
            # activity record back.
            session.flush()
            request.user = AnonymousUser()
        usersessionkit.track_activity(
            request,
            user=getattr(request, "user", None),
            session=session,
        )
        response = self.get_response(request)
        return response
