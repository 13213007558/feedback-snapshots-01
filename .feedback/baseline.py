from srp import _pysrp as srp
for password, expected in [(b"test-only-password", True), (b"wrong", False)]:
    salt, verifier = srp.create_salted_verification_key(b"alice", b"test-only-password", srp.SHA256, srp.NG_2048)
    client = srp.User(b"alice", password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    name, public = client.start_authentication()
    server = srp.Verifier(name, salt, verifier, public, hash_alg=srp.SHA256, ng_type=srp.NG_2048)
    salt, challenge = server.get_challenge()
    proof = client.process_challenge(salt, challenge)
    confirmation = server.verify_session(proof)
    if confirmation is not None: client.verify_session(confirmation)
    assert client.authenticated() is expected and server.authenticated() is expected
print("SRP pure Python: mutual authentication and wrong-password rejection passed")
