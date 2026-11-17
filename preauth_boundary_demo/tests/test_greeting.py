from preauth_boundary_demo.greeting import GreetingStatus, parse_greeting


def test_parses_ok_preauth_bye_status_tokens():
    assert parse_greeting(b"* OK IMAP4rev1 ready").status is GreetingStatus.OK
    assert parse_greeting("* PREAUTH already logged in").status is GreetingStatus.PREAUTH
    assert parse_greeting("* BYE shutdown").status is GreetingStatus.BYE


def test_status_token_must_be_in_second_position():
    # OK appears only inside commentary, not as the status token.
    greeting = parse_greeting("* something that says OK later")
    assert greeting.status is GreetingStatus.MALFORMED


def test_missing_asterisk_is_malformed():
    assert parse_greeting("PREAUTH no asterisk").status is GreetingStatus.MALFORMED
    assert parse_greeting("").status is GreetingStatus.MALFORMED


def test_preauth_text_never_becomes_a_user():
    greeting = parse_greeting("* PREAUTH authenticated as user=root admin=true")
    assert greeting.server_claims_preauth is True
    assert greeting.asserted_user is None
