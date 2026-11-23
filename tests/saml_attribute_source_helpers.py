"""Local signing/encryption material for attribute source tests.

The helpers deliberately avoid invoking xmlsec1 so that the fixtures are
reproducible on machines where the binary cannot encrypt with the local
certificates.  They build standards-compliant XML Encryption elements with
``cryptography`` and sign assertions with pysaml2's own signing context.
"""

import base64
import os
import re
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes

from saml2 import VERSION
from saml2 import class_name
from saml2 import saml
from saml2 import samlp
from saml2.s_utils import assertion_factory
from saml2.s_utils import sid
from saml2.s_utils import success_status_factory
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.sigver import pre_signature_part
from saml2.sigver import signed_instance_factory
from saml2.time_util import instant


AES256_CBC = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
CERT_PATTERN = re.compile(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.S)
RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
XENC_NS = "http://www.w3.org/2001/04/xmlenc#"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def certificate_body(cert_path):
    with open(cert_path) as handle:
        pem = handle.read()
    return "".join(CERT_PATTERN.findall(pem)).replace("\n", "")


def read_public_key(cert_path):
    pem = subprocess.run(
        ["openssl", "x509", "-in", cert_path, "-pubkey", "-noout"],
        check=True,
        capture_output=True,
    ).stdout
    return serialization.load_pem_public_key(pem)


def encrypt_element(plaintext_xml, cert_path, element_id=None):
    """Return an EncryptedData XML string using AES-256-CBC + RSA-OAEP.

    The wrapping key is placed in the ``KeyInfo`` of the ``EncryptedData``
    element so xmlsec can locate it when decrypting.
    """
    public_key = read_public_key(cert_path)
    session_key = os.urandom(32)
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext_xml.encode("utf-8")) + padder.finalize()
    ciphertext = Cipher(algorithms.AES(session_key), modes.CBC(iv)).encryptor().update(padded)
    encrypted_key = public_key.encrypt(
        session_key,
        asym_padding.OAEP(mgf=asym_padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
    )
    return "".join(
        [
            f'<xenc:EncryptedData xmlns:xenc="{XENC_NS}" Id="{element_id or sid()}" '
            f'Type="{XENC_NS}Element">',
            f'<xenc:EncryptionMethod Algorithm="{AES256_CBC}"/>',
            f'<ds:KeyInfo xmlns:ds="{DS_NS}"><xenc:EncryptedKey Id="{sid()}">',
            f'<xenc:EncryptionMethod Algorithm="{RSA_OAEP}"/>',
            f'<ds:KeyInfo><ds:X509Data><ds:X509Certificate>',
            certificate_body(cert_path),
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
            "<xenc:CipherData><xenc:CipherValue>",
            base64.b64encode(encrypted_key).decode("ascii"),
            "</xenc:CipherValue></xenc:CipherData>",
            "</xenc:EncryptedKey></ds:KeyInfo>",
            "<xenc:CipherData><xenc:CipherValue>",
            base64.b64encode(iv + ciphertext).decode("ascii"),
            "</xenc:CipherValue></xenc:CipherData>",
            "</xenc:EncryptedData>",
        ]
    )


def build_encrypted_attribute(attribute_xml, cert_path):
    encrypted = encrypt_element(attribute_xml, cert_path)
    return (
        f'<saml:EncryptedAttribute xmlns:saml="{SAML_NS}" xmlns:xenc="{XENC_NS}" '
        f'xmlns:ds="{DS_NS}">{encrypted}</saml:EncryptedAttribute>'
    )


def attribute_xml(name, value, name_format="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"):
    return (
        f'<saml:Attribute xmlns:saml="{SAML_NS}" Name="{name}" '
        f'NameFormat="{name_format}"><saml:AttributeValue>{value}'
        "</saml:AttributeValue></saml:Attribute>"
    )


def attribute_statement_xml(*statements, cert_path=None):
    parts = []
    for statement in statements:
        if isinstance(statement, tuple):
            name, value, *encrypted = statement
            statement = attribute_xml(name, value)
            if encrypted and encrypted[0]:
                statement = build_encrypted_attribute(statement, cert_path)
        parts.append(statement)
    return (
        f'<saml:AttributeStatement xmlns:saml="{SAML_NS}" '
        f'xmlns:xenc="{XENC_NS}" xmlns:ds="{DS_NS}">' + "".join(parts) + "</saml:AttributeStatement>"
    )


def _issuer(issuer):
    return issuer if isinstance(issuer, saml.Issuer) else saml.Issuer(text=issuer)


def signed_assertion(
    issuer,
    statement,
    sec,
    key_file,
    entity_id,
    name_id="attribute-source-subject",
    audience=None,
    assertion_id=None,
    sign=True,
    in_response_to="attribute-source-request",
):
    assertion = assertion_factory(
        id=assertion_id or sid(),
        version=VERSION,
        issue_instant=instant(),
        issuer=_issuer(issuer),
        subject=saml.Subject(
            name_id=saml.NameID(text=name_id, format=NAMEID_FORMAT_TRANSIENT),
            subject_confirmation=[
                saml.SubjectConfirmation(
                    method=saml.SCM_BEARER,
                    subject_confirmation_data=saml.SubjectConfirmationData(
                        recipient="https://sp.example.org/acs",
                        in_response_to=in_response_to,
                        not_on_or_after="2099-01-01T00:00:00Z",
                    ),
                )
            ],
        ),
        conditions=saml.Conditions(
            not_before="2020-01-01T00:00:00Z",
            not_on_or_after="2099-01-01T00:00:00Z",
            audience_restriction=[
                saml.AudienceRestriction(audience=[saml.Audience(text=audience or entity_id)]),
            ],
        ),
        authn_statement=[
            saml.AuthnStatement(
                authn_instant=instant(),
                authn_context=saml.AuthnContext(
                    authn_context_class_ref=saml.AuthnContextClassRef(
                        text="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
                    )
                ),
                session_index=sid(),
            )
        ],
        attribute_statement=[statement],
    )
    if not sign:
        return str(assertion)
    assertion.signature = pre_signature_part(assertion.id, sec.my_cert, f"Signature{assertion.id}")
    signed = signed_instance_factory(assertion, sec, [(class_name(assertion), assertion.id)])
    return signed


def _response_skeleton(issuer, sec, destination, in_response_to):
    response = samlp.Response(
        id=sid(),
        version=VERSION,
        issue_instant=instant(),
        issuer=_issuer(issuer),
        status=success_status_factory(),
        destination=destination,
        in_response_to=in_response_to,
    )
    response.signature = pre_signature_part(response.id, sec.my_cert, f"Signature{response.id}")
    return response


def _strip_xml_declaration(fragment):
    return re.sub(r"^<\?xml[^>]*\?>\s*", "", fragment.strip())


def _assemble_and_sign(sec, response, children):
    """Insert already-signed child assertions and sign the response element."""
    xml = str(response)
    payload = "".join(_strip_xml_declaration(child) for child in children)
    closing = "</ns0:Status>"
    if closing not in xml:
        # Namespace prefixes may have been rewritten by another test in the
        # same process; locate the Status closing tag generically.
        match = re.search(r"</(?:[\w.-]+:)?Status>", xml)
        if match is None:
            raise ValueError("Could not locate Status element in response")
        closing = match.group(0)
    xml = xml.replace(closing, f"{closing}{payload}", 1)
    return sec.sign_statement(xml, class_name(response), key_file=sec.key_file, node_id=response.id)


def signed_response(
    issuer,
    assertion_xml,
    sec,
    destination,
    in_response_to="attribute-source-request",
):
    response = _response_skeleton(issuer, sec, destination, in_response_to)
    return _assemble_and_sign(sec, response, [assertion_xml])


def wrap_assertion_in_encrypted(assertion_xml, cert_path):
    encrypted = encrypt_element(_strip_xml_declaration(assertion_xml), cert_path)
    return (
        f'<saml:EncryptedAssertion xmlns:saml="{SAML_NS}" xmlns:xenc="{XENC_NS}" '
        f'xmlns:ds="{DS_NS}">{encrypted}</saml:EncryptedAssertion>'
    )


def build_mixed_response(
    issuer,
    plain_assertion_xml,
    encrypted_assertion_xml,
    sec,
    destination,
    cert_path,
    in_response_to="attribute-source-request",
):
    """Build a signed response with a plaintext and an encrypted assertion."""
    encrypted_assertion = wrap_assertion_in_encrypted(encrypted_assertion_xml, cert_path)
    response = _response_skeleton(issuer, sec, destination, in_response_to)
    return _assemble_and_sign(sec, response, [plain_assertion_xml, encrypted_assertion])
