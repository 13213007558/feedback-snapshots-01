#!/usr/bin/env python3
"""Generate the SAML canonicalization compatibility fixtures.

Run from the repository root:

    python3 test/c14n_matrix/generate_fixtures.py

Requirements: xmlsec1, xmllint, openssl, python3.

Signature layers included here:

* Response/Assertion fixtures are signed by xmlsec1. The canonical bytes
  recorded in expected.json are xmlsec1's own PreDigest (Reference) and
  PreSigned (SignedInfo) buffers, so they do not come from Nokogiri or
  ruby-saml.
* The WithComments fixture is signed by canonicalizing with
  ``xmllint --exc-c14n`` and signing with ``openssl dgst`` because xmlsec1
  1.3.13 drops comments from Reference digests even when the algorithm URI
  says #WithComments.
* Negative fixtures are text edits of a validly signed document. They are
  intentionally not re-signed: verification must reject them.

Every fixture keeps the exact bytes that were signed. Re-formatting these
files invalidates the digests, which is part of what the matrix records.
"""
import base64
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.getcwd()
OUT = os.path.join(ROOT, "test/c14n_matrix/fixtures")
WORK = os.path.join("/tmp/claude-501", "ruby-saml-c14n-matrix")
KEY = os.path.join(ROOT, "test/certificates/ruby-saml.key")
CERT = os.path.join(ROOT, "test/certificates/ruby-saml.crt")
XMLSEC = "xmlsec1"

C14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
C14N_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
C14N10 = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DSIG = "http://www.w3.org/2000/09/xmldsig#"

os.makedirs(OUT, exist_ok=True)
os.makedirs(WORK, exist_ok=True)

# --------------------------------------------------------------------------
# Document templates
# --------------------------------------------------------------------------

ASSERTION_BODY = """    <saml:Issuer>https://idp.example.com</saml:Issuer>
{comment}    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2035-01-01T00:00:00Z" Recipient="https://sp.example.com/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2035-01-01T00:00:00Z">
      <saml:AudienceRestriction><saml:Audience>https://sp.example.com/saml</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2020-01-01T00:00:00Z" SessionIndex="session1">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
"""

def signature(uri, si_c14n=C14N, si_prefixes=None,
              ref_c14n=C14N, ref_prefixes=None, omit_ref_c14n=False):
    def inclusive(prefixes):
        if not prefixes:
            return ""
        return ('<ec:InclusiveNamespaces xmlns:ec="%s" PrefixList="%s"/>'
                % (C14N, prefixes))
    ref_transform = "" if omit_ref_c14n else (
        '            <ds:Transform Algorithm="%s">%s</ds:Transform>\n'
        % (ref_c14n, inclusive(ref_prefixes)))
    return """    <ds:Signature xmlns:ds="{dsig}">
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="{si_c14n}">{si_inc}</ds:CanonicalizationMethod>
        <ds:SignatureMethod Algorithm="{rsa}"/>
        <ds:Reference URI="#{uri}">
          <ds:Transforms>
            <ds:Transform Algorithm="{enveloped}"/>
{ref_transform}          </ds:Transforms>
          <ds:DigestMethod Algorithm="{sha256}"/>
          <ds:DigestValue/>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue/>
      <ds:KeyInfo><ds:KeyName>matrix</ds:KeyName></ds:KeyInfo>
    </ds:Signature>
""".format(dsig=DSIG, si_c14n=si_c14n, si_inc=inclusive(si_prefixes),
           rsa=RSA_SHA256, uri=uri, enveloped=ENVELOPED,
           ref_transform=ref_transform, sha256=SHA256)

def response(assertion_sig, root_attrs="", comment=""):
    return """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" {root_attrs}ID="resp1" Version="2.0" IssueInstant="2020-01-01T00:00:00Z" Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion {assertion_attrs} Version="2.0" IssueInstant="2020-01-01T00:00:00Z">
{body}{assertion_sig}  </saml:Assertion>
</samlp:Response>
""".format(root_attrs=root_attrs,
           assertion_attrs='xmlns:foo="urn:foo" ID="assert1"',
           body=ASSERTION_BODY.format(comment=comment),
           assertion_sig=assertion_sig)

# --------------------------------------------------------------------------
# xmlsec1 helper
# --------------------------------------------------------------------------

CASES = {}
NEGATIVE = {}

def record(case, doc, ref_bytes, si_bytes):
    digest = re.sub(r"\s+", "",
                    re.search(r"<ds:DigestValue>([^<]*)</ds:DigestValue>", doc).group(1))
    assert base64.b64encode(hashlib.sha256(ref_bytes).digest()).decode() == digest, case
    CASES[case] = {
        "fixture": case + ".xml",
        "reference_canonical_b64": base64.b64encode(ref_bytes).decode(),
        "reference_digest_b64": digest,
        "signed_info_canonical_b64": base64.b64encode(si_bytes).decode(),
        "signed_info_sha256_b64": base64.b64encode(hashlib.sha256(si_bytes).digest()).decode(),
    }
    with open(os.path.join(OUT, case + ".xml"), "w") as handle:
        handle.write(doc)

def xmlsec_buffers(stdout):
    def buf(label):
        match = re.search(r"== %s - start buffer:\n(.*?)== %s - end buffer" % (label, label),
                          stdout, re.S)
        return bytes.fromhex(re.sub(r"\s+", "", match.group(1))) if match else None
    return buf("PreDigest data"), buf("PreSigned data")

def sign_xmlsec(case, xml, ids=("Assertion",), node="assert1"):
    src = os.path.join(WORK, case + ".tmpl.xml")
    dst = os.path.join(WORK, case + ".signed.xml")
    with open(src, "w") as handle:
        handle.write(xml)
    args = [XMLSEC, "--sign", "--privkey-pem:matrix", KEY + "," + CERT]
    for identifier in ids:
        args += ["--id-attr:ID", identifier]
    args += ["--node-id", node, "--store-references", "--store-signatures",
             "--output", dst, src]
    proc = subprocess.run(args, capture_output=True, text=True)
    if not os.path.exists(dst):
        sys.exit("%s: xmlsec1 signing failed\n%s\n%s"
                 % (case, proc.stdout[-2000:], proc.stderr[-1000:]))
    doc = open(dst).read()
    ref_bytes, si_bytes = xmlsec_buffers(proc.stdout)
    if not ref_bytes or not si_bytes:
        sys.exit("%s: xmlsec1 did not emit canonical buffers" % case)
    record(case, doc, ref_bytes, si_bytes)

def add_negative(name, doc, reason):
    with open(os.path.join(OUT, name + ".xml"), "w") as handle:
        handle.write(doc)
    NEGATIVE[name] = {"fixture": name + ".xml", "reason": reason}

# --------------------------------------------------------------------------
# 1. Exclusive c14n and InclusiveNamespaces on the Reference
# --------------------------------------------------------------------------

def response_case(name, sig, root_attrs="", comment=""):
    sign_xmlsec(name, response(sig, root_attrs, comment))

# The assertion declares foo. InclusiveNamespaces naming foo on the
# Reference brings the declaration into the Reference canonical form.
response_case("exclusive_prefix_list",
              signature("assert1", ref_prefixes="xs foo"))
response_case("exclusive_no_prefix_list", signature("assert1"))

# The SignedInfo prefix list must not become a Reference parameter.
response_case("signed_info_prefix_only",
              signature("assert1", si_prefixes="xs foo"))
# And a Reference prefix list must not be applied to SignedInfo.
response_case("reference_prefix_only",
              signature("assert1", ref_prefixes="xs foo"))

# --------------------------------------------------------------------------
# 2. Default namespace and ancestor declarations
# --------------------------------------------------------------------------

default_ns = 'xmlns="urn:oasis:names:tc:SAML:2.0:protocol" '
response_case("default_ns_reference_included",
              signature("assert1", ref_prefixes="#default"), default_ns)
response_case("default_ns_reference_omitted",
              signature("assert1"), default_ns)
response_case("default_ns_signed_info_only",
              signature("assert1", si_prefixes="#default"), default_ns)
# foo is declared on the Assertion, not the Response: only exclusive c14n
# can pull an ancestor declaration into the SignedInfo canonical form, and
# only because SignedInfo names it.
response_case("signed_info_ancestor_prefix",
              signature("assert1", si_prefixes="foo"))

# --------------------------------------------------------------------------
# 3. Per-layer algorithms: Reference default and SignedInfo/Reference split
# --------------------------------------------------------------------------

# XMLDSig defaults a Reference without a c14n transform to inclusive c14n
# 1.0, not to the SignedInfo canonicalization method.
response_case("reference_without_c14n_transform",
              signature("assert1", omit_ref_c14n=True))
response_case("signed_info_inclusive",
              signature("assert1", si_c14n=C14N10))

# --------------------------------------------------------------------------
# 4. Comments
# --------------------------------------------------------------------------

response_case("exclusive_comments_dropped",
              signature("assert1"),
              comment="    <!-- payload comment -->\n")

def xmllint_c14n(xml):
    src = os.path.join(WORK, "_xmllint_in.xml")
    with open(src, "w") as handle:
        handle.write(xml)
    proc = subprocess.run(["xmllint", "--exc-c14n", src],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit("xmllint failed: %s" % proc.stderr)
    return proc.stdout.encode()

def slice_element(doc, name):
    match = re.search(r"<%s[ >].*?</%s>" % (name, name), doc, re.S)
    if not match:
        sys.exit("could not find %s" % name)
    return match.group(0)

def in_scope_declarations(doc):
    match = re.search(r"<samlp:Response([^>]*)>", doc)
    attrs = match.group(1)
    declarations = dict(re.findall(r'xmlns(?::[\w.-]+)?="[^"]*"', attrs) and
                        [(m.group(0).split("=")[0], m.group(0)) for m in
                         re.finditer(r'xmlns(?::[\w.-]+)?="[^"]*"', attrs)])
    return " ".join(declarations.values())

def standalone(xml_element, inherited):
    # Give the extracted subtree the same in-scope declarations it had in the
    # original document. Exclusive c14n only renders visibly utilized
    # declarations, so this does not add bytes to the canonical form, but it
    # does let xmllint resolve prefixes named in InclusiveNamespaces.
    return re.sub(r"^<([\w:.-]+)", r"<\1 " + inherited, xml_element, count=1)

def build_with_comments():
    base = response(signature("assert1", si_c14n=C14N_COMMENTS,
                              ref_c14n=C14N_COMMENTS),
                    comment="    <!-- payload comment -->\n")
    base = base.replace("<ds:SignedInfo>",
                        "<ds:SignedInfo><!-- signed info comment -->", 1)
    inherited = in_scope_declarations(base)

    assertion = slice_element(base, "saml:Assertion")
    assertion_body = re.sub(r"<ds:Signature.*?</ds:Signature>", "", assertion,
                            count=1, flags=re.S)
    ref_bytes = xmllint_c14n(standalone(assertion_body, inherited))
    digest = base64.b64encode(hashlib.sha256(ref_bytes).digest()).decode()

    signed_info = slice_element(base, "ds:SignedInfo")
    signed_info = signed_info.replace("<ds:DigestValue/>",
                                      "<ds:DigestValue>%s</ds:DigestValue>" % digest)
    si_bytes = xmllint_c14n(standalone(signed_info,
        inherited + ' xmlns:ds="%s"' % DSIG))

    si_file = os.path.join(WORK, "with_comments_si.bin")
    sig_file = os.path.join(WORK, "with_comments_sig.bin")
    with open(si_file, "wb") as handle:
        handle.write(si_bytes)
    subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY,
                    "-out", sig_file, si_file], check=True)
    signature_value = base64.b64encode(open(sig_file, "rb").read()).decode()

    doc = base.replace("<ds:SignatureValue/>",
                       "<ds:SignatureValue>%s</ds:SignatureValue>" % signature_value, 1)
    doc = doc.replace("<ds:DigestValue/>",
                      "<ds:DigestValue>%s</ds:DigestValue>" % digest, 1)
    record("exclusive_with_comments", doc, ref_bytes, si_bytes)

build_with_comments()

# --------------------------------------------------------------------------
# 5. Two signature layers with different algorithms
# --------------------------------------------------------------------------

def build_two_layers():
    response_sig = signature("resp1", ref_c14n=C14N10)
    assertion_sig = signature("assert1", ref_prefixes="xs foo")
    xml = response(assertion_sig)
    xml = xml.replace("  <samlp:Status>", response_sig + "  <samlp:Status>", 1)

    first = os.path.join(WORK, "two_layers_first.xml")
    second = os.path.join(WORK, "two_layers_second.xml")
    with open(first, "w") as handle:
        handle.write(xml)
    args = [XMLSEC, "--sign", "--privkey-pem:matrix", KEY + "," + CERT,
            "--id-attr:ID", "Response", "--id-attr:ID", "Assertion",
            "--node-id", "assert1", "--store-references", "--store-signatures",
            "--output", second, first]
    proc = subprocess.run(args, capture_output=True, text=True)
    if not os.path.exists(second):
        sys.exit("two layers: xmlsec1 failed\n%s" % proc.stdout[-2000:])
    assertion_ref, assertion_si = xmlsec_buffers(proc.stdout)

    third = os.path.join(WORK, "two_layers_third.xml")
    proc2 = subprocess.run([XMLSEC, "--sign", "--privkey-pem:matrix",
                            KEY + "," + CERT,
                            "--id-attr:ID", "Response", "--id-attr:ID", "Assertion",
                            "--node-id", "resp1", "--store-references",
                            "--store-signatures", "--output", third, second],
                           capture_output=True, text=True)
    if not os.path.exists(third):
        sys.exit("two layers: xmlsec1 second pass failed\n%s" % proc2.stdout[-2000:])
    response_ref, response_si = xmlsec_buffers(proc2.stdout)
    doc = open(third).read()

    digest = re.sub(r"\s+", "",
                    re.search(r"<ds:DigestValue>([^<]*)</ds:DigestValue>", doc).group(1))
    assert base64.b64encode(hashlib.sha256(response_ref).digest()).decode() == digest
    CASES["two_signature_layers"] = {
        "fixture": "two_signature_layers.xml",
        # ruby-saml validates the first signature in document order: the
        # Response layer, whose Reference transform is inclusive c14n 1.0.
        "reference_canonical_b64": base64.b64encode(response_ref).decode(),
        "reference_digest_b64": digest,
        "signed_info_canonical_b64": base64.b64encode(response_si).decode(),
        "signed_info_sha256_b64": base64.b64encode(hashlib.sha256(response_si).digest()).decode(),
        "secondary_layer": {
            "reference_canonical_b64": base64.b64encode(assertion_ref).decode(),
            "signed_info_canonical_b64": base64.b64encode(assertion_si).decode(),
        },
    }
    with open(os.path.join(OUT, "two_signature_layers.xml"), "w") as handle:
        handle.write(doc)

build_two_layers()


# --------------------------------------------------------------------------
# 6. Signature node moved into a different namespace context
# --------------------------------------------------------------------------

def build_moved_signature():
    xml = response(signature("assert1", si_prefixes="xs foo"))
    sign_xmlsec("signature_in_place", xml)
    signed = open(os.path.join(OUT, "signature_in_place.xml")).read()
    block = re.search(r"<ds:Signature.*?</ds:Signature>", signed, re.S).group(0)
    # Move only the Signature element, leaving the surrounding whitespace text
    # nodes in place so the Reference digest is unchanged. SignedInfo changes
    # context because foo is declared on the Assertion, not on Response,
    # while SignedInfo names foo in InclusiveNamespaces.
    moved = signed.replace(block, "", 1)
    moved = moved.replace("  <samlp:Status>", block + "  <samlp:Status>", 1)
    with open(os.path.join(OUT, "signature_moved_out_of_scope.xml"), "w") as handle:
        handle.write(moved)
    NEGATIVE["signature_moved_out_of_scope"] = {
        "fixture": "signature_moved_out_of_scope.xml",
        "reason": ("SignedInfo names prefix foo in InclusiveNamespaces, but foo "
                   "is declared on the Assertion. Moving the Signature out of the "
                   "Assertion changes the inherited context, so the SignedInfo "
                   "canonical bytes differ from what was signed."),
    }

build_moved_signature()

# --------------------------------------------------------------------------
# 7. Negative fixtures: flip one declared parameter, keep the signature
# --------------------------------------------------------------------------

def tamper(name, source, old, new, reason):
    doc = open(os.path.join(OUT, source + ".xml")).read()
    if old not in doc:
        sys.exit("%s: pattern not found for %s" % (name, source))
    add_negative(name, doc.replace(old, new, 1), reason)

tamper("tampered_reference_prefix_removed", "exclusive_prefix_list",
       '<ds:Transform Algorithm="%s"><ec:InclusiveNamespaces '
       'xmlns:ec="%s" PrefixList="xs foo"/></ds:Transform>' % (C14N, C14N),
       '<ds:Transform Algorithm="%s"/>' % C14N,
       "Removing the Reference InclusiveNamespaces drops xmlns:foo from the "
       "canonical form; the digest no longer matches.")

tamper("tampered_reference_prefix_added", "exclusive_no_prefix_list",
       '<ds:Transform Algorithm="%s"/>' % C14N,
       '<ds:Transform Algorithm="%s"><ec:InclusiveNamespaces '
       'xmlns:ec="%s" PrefixList="xs foo"/></ds:Transform>' % (C14N, C14N),
       "Adding an InclusiveNamespaces parameter to the Reference changes the "
       "digest input; the original digest must not verify.")

tamper("tampered_signed_info_prefix_changed", "signed_info_prefix_only",
       'PrefixList="xs foo"', 'PrefixList="xs bar"',
       "Changing the SignedInfo prefix list changes SignedInfo canonical bytes, "
       "so the RSA signature must fail.")

tamper("tampered_default_namespace_dropped", "default_ns_reference_included",
       ' PrefixList="#default"', '',
       "Dropping #default removes the inherited default namespace from the "
       "canonical form; the digest must fail.")

# --------------------------------------------------------------------------
# 8. Metadata entry point (README documented verification flow)
# --------------------------------------------------------------------------

METADATA = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="meta1" entityID="https://sp.example.com/saml">
  <ds:Signature xmlns:ds="{dsig}">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="{c14n}"/>
      <ds:SignatureMethod Algorithm="{rsa}"/>
      <ds:Reference URI="#meta1">
        <ds:Transforms>
          <ds:Transform Algorithm="{enveloped}"/>
          <ds:Transform Algorithm="{c14n}"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="{sha256}"/>
        <ds:DigestValue/>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue/>
    <ds:KeyInfo><ds:KeyName>matrix</ds:KeyName></ds:KeyInfo>
  </ds:Signature>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/acs" index="0" isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
""".format(dsig=DSIG, c14n=C14N, rsa=RSA_SHA256, enveloped=ENVELOPED, sha256=SHA256)

metadata_src = os.path.join(WORK, "metadata.tmpl.xml")
open(metadata_src, "w").write(METADATA)
proc = subprocess.run([XMLSEC, "--sign", "--privkey-pem:matrix", KEY + "," + CERT,
                       "--id-attr:ID", "EntityDescriptor",
                       "--store-references", "--store-signatures",
                       "--output", os.path.join(WORK, "metadata.signed.xml"),
                       metadata_src], capture_output=True, text=True)
if not os.path.exists(os.path.join(WORK, "metadata.signed.xml")):
    sys.exit("metadata signing failed\n%s" % proc.stdout[-2000:])
metadata_doc = open(os.path.join(WORK, "metadata.signed.xml")).read()
ref_bytes, si_bytes = xmlsec_buffers(proc.stdout)
record("signed_metadata", metadata_doc, ref_bytes, si_bytes)

# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

with open(os.path.join(OUT, "expected.json"), "w") as handle:
    json.dump({"cases": CASES, "negative": NEGATIVE}, handle,
              indent=2, sort_keys=True)
print("generated %d positive and %d negative fixtures"
      % (len(CASES), len(NEGATIVE)))
