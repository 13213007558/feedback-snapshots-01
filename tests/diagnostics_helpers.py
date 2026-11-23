"""Offline fixtures for the response diagnostics contract tests."""

from pathlib import Path

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.cert import OpenSSLWrapper
from saml2.cert import read_cert_from_file
from saml2.config import config_factory
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NameID
from saml2.server import Server


IDP_ENTITY_ID = "https://idp.privacy.example/metadata"
SP_ENTITY_ID = "https://sp.privacy.example/metadata"
ACS_URL = "https://sp.privacy.example/acs"
SSO_URL = "https://idp.privacy.example/sso"

PRIVACY_MARKERS = (
    "PRIVACY-MARKER-NAMEID",
    "PRIVACY-MARKER-VALUE",
    "privacy-marker@example.invalid",
    "PRIVACY-MARKER-RAW-XML",
)


def _cert_info(common_name):
    return {
        "cn": common_name,
        "country_code": "zz",
        "state": "zz",
        "city": "zz",
        "organization": "zz",
        "organization_unit": "zz",
    }


class SyntheticFederation:
    """Create local trust material and signed IdP responses for one test."""

    def __init__(self, workdir):
        self.workdir = Path(workdir)
        self.osw = OpenSSLWrapper()

    def _write(self, name, payload):
        path = self.workdir / name
        if isinstance(payload, bytes):
            path.write_bytes(payload)
        else:
            path.write_text(payload)
        return str(path)

    def generate_certificate(self, common_name):
        certificate, key = self.osw.create_certificate(_cert_info(common_name), request=False, key_length=2048)
        cert_path = self._write(f"{common_name}.crt", certificate)
        key_path = self._write(f"{common_name}.key", key)
        return cert_path, key_path

    def metadata_for(self, cert_path, filename, key_name=None):
        certificate = read_cert_from_file(cert_path)
        key_descriptor = (
            f'<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            f"<ds:X509Data><ds:X509Certificate>{certificate}</ds:X509Certificate></ds:X509Data>"
            f"</ds:KeyInfo></md:KeyDescriptor>"
        )
        if key_name:
            key_descriptor = key_descriptor.replace(
                "<ds:KeyInfo", f"<ds:KeyName>{key_name}</ds:KeyName><ds:KeyInfo", 1
            )
        metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY_ID}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    {key_descriptor}
    <md:SingleSignOnService Binding="{BINDING_HTTP_REDIRECT}" Location="{SSO_URL}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""
        return self._write(filename, metadata)

    def sp_metadata(self):
        metadata = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{SP_ENTITY_ID}">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                      AuthnRequestsSigned="false" WantAssertionsSigned="false">
    <md:AssertionConsumerService Binding="{BINDING_HTTP_POST}" Location="{ACS_URL}" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""
        return self._write("sp-metadata.xml", metadata)

    def idp_server(self, cert_path, key_path, sp_metadata_path):
        config = {
            "entityid": IDP_ENTITY_ID,
            "key_file": key_path,
            "cert_file": cert_path,
            "xmlsec_binary": self.xmlsec_binary,
            "metadata": [{"class": "saml2.mdstore.MetaDataFile", "metadata": [(sp_metadata_path,)]}],
            "accepted_time_diff": 300,
        }
        return Server(config=config_factory("idp", config))

    @property
    def xmlsec_binary(self):
        from pathutils import xmlsec_path

        return xmlsec_path

    def sp_config(self, metadata_path, attribute_map_dir=None):
        config = {
            "entityid": SP_ENTITY_ID,
            "key_file": str(self.workdir / "sp.key"),
            "cert_file": str(self.workdir / "sp.crt"),
            "xmlsec_binary": self.xmlsec_binary,
            "metadata": [{"class": "saml2.mdstore.MetaDataFile", "metadata": [(metadata_path,)]}],
            "accepted_time_diff": 300,
        }
        if attribute_map_dir:
            config["attribute_map_dir"] = str(attribute_map_dir)
        return config_factory("sp", config)

    @staticmethod
    def make_name_id():
        return NameID(format=NAMEID_FORMAT_PERSISTENT, text="PRIVACY-MARKER-NAMEID")

    @staticmethod
    def identity():
        return {
            "eduPersonPrincipalName": ["privacy-marker@example.invalid"],
            "givenName": ["PRIVACY-MARKER-VALUE"],
        }

    def authn_response(self, server, in_response_to):
        response = server.create_authn_response(
            self.identity(),
            in_response_to,
            ACS_URL,
            SP_ENTITY_ID,
            name_id=self.make_name_id(),
            authn={
                "class_ref": INTERNETPROTOCOLPASSWORD,
                "authn_auth": "https://idp.privacy.example/login",
            },
            sign_response=True,
        )
        return str(response)

    def attribute_map_missing_principal_name(self):
        """Copies the URI attribute map but drops eduPersonPrincipalName.

        Mapping the assertion then succeeds for one attribute and silently
        drops the other, which is what a support ticket must be able to prove.
        """
        source = Path(__file__).parent.parent / "src" / "saml2" / "attributemaps" / "saml_uri.py"
        lines = source.read_text().splitlines(keepends=True)
        overridden = "".join(
            line for line in lines if 'f"{EDUPERSON_OID}6": "eduPersonPrincipalName"' not in line
        )
        if overridden == "".join(lines):
            raise AssertionError("Could not create the mapping-failure attribute map")
        map_dir = self.workdir / "attribute-maps-mapping-failure"
        map_dir.mkdir()
        # A unique module name avoids clashing with an already imported
        # saml2.attributemaps module when the whole test suite runs together.
        (map_dir / "response_diagnostics_mapping_failure.py").write_text(overridden)
        return map_dir

