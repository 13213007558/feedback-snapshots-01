from __future__ import annotations

from unittest.mock import Mock

from kombu.exceptions import HttpError, ReplyNotAllowedError


class test_HttpError:

    def test_str(self) -> None:
        assert str(HttpError(200, 'msg', Mock(name='response')))


class test_ReplyNotAllowedError:

    def test_message_names_destination_and_allowed_set(self) -> None:
        error = ReplyNotAllowedError('rogue', {'approved'})
        assert error.reply_to == 'rogue'
        assert error.allowed == {'approved'}
        message = str(error)
        assert 'rogue' in message
        assert 'approved' in message

    def test_message_without_allowed_set(self) -> None:
        error = ReplyNotAllowedError('rogue')
        assert error.reply_to == 'rogue'
        assert error.allowed is None
        assert 'rogue' in str(error)

