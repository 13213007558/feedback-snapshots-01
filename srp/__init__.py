
_mod     = None

try:
    import srp._ctsrp
    _mod = srp._ctsrp
except (ImportError, OSError):
    pass

if not _mod:
    import srp._pysrp
    _mod = srp._pysrp

User                           = _mod.User
Verifier                       = _mod.Verifier
create_salted_verification_key = _mod.create_salted_verification_key

SHA1      = _mod.SHA1
SHA224    = _mod.SHA224
SHA256    = _mod.SHA256
SHA384    = _mod.SHA384
SHA512    = _mod.SHA512

NG_1024   = _mod.NG_1024
NG_2048   = _mod.NG_2048
NG_4096   = _mod.NG_4096
NG_8192   = _mod.NG_8192
NG_CUSTOM = _mod.NG_CUSTOM

rfc5054_enable   = _mod.rfc5054_enable
no_username_in_x = _mod.no_username_in_x

# Session-scoped compatibility configuration. Pass one of these (or a
# registered identifier string) as ``config=`` to pin the hash-input mode for
# a single verifier creation / handshake instead of relying on the
# process-global switches above.
SrpConfig                        = _mod.SrpConfig
register_srp_config              = _mod.register_srp_config
srp_config_identifier            = _mod.srp_config_identifier

SRP_CONFIG_LEGACY                = _mod.SRP_CONFIG_LEGACY
SRP_CONFIG_RFC5054               = _mod.SRP_CONFIG_RFC5054
SRP_CONFIG_NO_USERNAME           = _mod.SRP_CONFIG_NO_USERNAME
SRP_CONFIG_RFC5054_NO_USER       = _mod.SRP_CONFIG_RFC5054_NO_USER
DEFAULT_SRP_CONFIG_ID            = _mod.DEFAULT_SRP_CONFIG_ID
