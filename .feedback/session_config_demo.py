"""End-to-end demonstration of session-scoped SRP compatibility modes.

Two tenants require different modes:

* tenant A uses the historical pysrp hash inputs
* tenant B uses RFC 5054 padding with the username kept in x

Registration and authentication for the two tenants are interleaved and the
legacy process-global switches are deliberately flipped between the two
handshake steps. Each session keeps using the mode it was created with, so
legal combinations still authenticate while cross-mode proofs are rejected
without any retry against weaker parameters.
"""

import srp
import srp._pysrp as mod

HASH_ALG, NG_TYPE = srp.SHA256, srp.NG_2048
USERNAME, PASSWORD = b'demo-user', b'demo-password'

# A real server persists this identifier next to salt and verifier.
database = {}


def register(tenant, config_id):
    salt, verifier = mod.create_salted_verification_key(
        USERNAME, PASSWORD, HASH_ALG, NG_TYPE, config=config_id)
    database[tenant] = (salt, verifier, config_id)
    print('registered %-7s mode=%s' % (tenant, config_id))


def authenticate(tenant, client_config_id):
    salt, verifier, stored_id = database[tenant]
    client = mod.User(USERNAME, PASSWORD, HASH_ALG, NG_TYPE,
                      config=client_config_id)
    _, public_a = client.start_authentication()
    # The server rebuilds the mode from the identifier saved with the record.
    server = mod.Verifier(USERNAME, salt, verifier, public_a,
                          HASH_ALG, NG_TYPE, config=stored_id)
    server_salt, challenge = server.get_challenge()
    proof = client.process_challenge(server_salt, challenge)
    hamk = server.verify_session(proof)
    if hamk is not None:
        client.verify_session(hamk)
    return client.authenticated(), server.authenticated()


print('--- interleaved registration, globals flipped in between ---')
register('A', srp.SRP_CONFIG_LEGACY)
srp.rfc5054_enable()
srp.no_username_in_x()
register('B', srp.SRP_CONFIG_RFC5054)
srp.rfc5054_enable(False)
srp.no_username_in_x(False)

print('--- legal combinations while globals keep changing ---')
srp.rfc5054_enable()
ok_a = authenticate('A', srp.SRP_CONFIG_LEGACY)
srp.no_username_in_x()
ok_b = authenticate('B', srp.SRP_CONFIG_RFC5054)
srp.rfc5054_enable(False)
srp.no_username_in_x(False)
print('tenant A (legacy record, legacy client):', ok_a)
print('tenant B (rfc5054 record, rfc5054 client):', ok_b)
assert ok_a == (True, True) and ok_b == (True, True)

print('--- cross-mode proofs are always rejected, no weaker retry ---')
cross = authenticate('B', srp.SRP_CONFIG_LEGACY)
print('rfc5054 record probed with a legacy client:', cross)
assert cross == (False, False)
cross = authenticate('A', srp.SRP_CONFIG_RFC5054)
print('legacy record probed with an rfc5054 client:', cross)
assert cross == (False, False)

print('all session-config invariants hold')
