# Copyright 2018 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import atexit
import base64
import copy
import datetime
import json
import logging
import os
import platform
import subprocess
import tempfile
from collections import namedtuple

import oauthlib.oauth2
import urllib3
import yaml
from requests_oauthlib import OAuth2Session

from kubernetes.client import ApiClient, Configuration
from kubernetes.config.exec_provider import ExecProvider

from .config_exception import ConfigException
from .dateutil import UTC, format_rfc3339, parse_rfc3339
from .kubeconfig_source import (CAPABILITY_AUTHENTICATE, CAPABILITY_DESCRIBE,
                                CAPABILITY_EXEC, KubeConfigAudit,
                                KubeConfigAuditRecord,
                                KubeConfigSourceError,
                                KubeConfigSourcePolicy,
                                canonical_source_path, describe_material)

try:
    import google.auth
    import google.auth.transport.requests
    google_auth_available = True
except ImportError:
    google_auth_available = False



EXPIRY_SKEW_PREVENTION_DELAY = datetime.timedelta(minutes=5)
KUBE_CONFIG_DEFAULT_LOCATION = os.environ.get('KUBECONFIG', '~/.kube/config')
ENV_KUBECONFIG_PATH_SEPARATOR = ';' if platform.system() == 'Windows' else ':'
_temp_files = {}


def _cleanup_temp_files():
    global _temp_files
    for temp_file in _temp_files.values():
        try:
            os.remove(temp_file)
        except OSError:
            pass
    _temp_files = {}


def _create_temp_file_with_content(content, temp_file_path=None, force_recreate=False):
    if len(_temp_files) == 0:
        atexit.register(_cleanup_temp_files)
    # Because we may change context several times, try to remember files we
    # created and reuse them at a small memory cost.
    content_key = str(content)
    if not force_recreate and content_key in _temp_files:
        return _temp_files[content_key]
    if temp_file_path and not os.path.isdir(temp_file_path):
        os.makedirs(name=temp_file_path)
    fd, name = tempfile.mkstemp(dir=temp_file_path)
    os.close(fd)
    _temp_files[content_key] = name
    with open(name, 'wb') as fd:
        fd.write(content.encode() if isinstance(content, str) else content)
    return name


def _describe_material_field(obj, file_key, resolved_file, origin=None):
    """Describe the certificate material a kubeconfig field produced.

    ``data`` wins over ``file`` in :class:`FileOrData`, so the audit record
    follows the same precedence and records whether the value was inline or a
    path.  ``origin`` marks material supplied by something other than the
    kubeconfig entry (an exec plugin).
    """

    if not obj:
        return None
    data_key = file_key + '-data'
    if data_key in obj and obj[data_key]:
        return describe_material(
            obj[data_key], resolved_file, kind='data', origin=origin)
    if file_key in obj:
        return describe_material(
            obj[file_key], resolved_file, kind='path', origin=origin)
    return describe_material(None, resolved_file, origin=origin)


def _is_expired(expiry):
    return ((parse_rfc3339(expiry) - EXPIRY_SKEW_PREVENTION_DELAY) <=
            datetime.datetime.now(tz=UTC))


class FileOrData:
    """Utility class to read content of obj[%data_key_name] or file's
     content of obj[%file_key_name] and represent it as file or data.
     Note that the data is preferred. The obj[%file_key_name] will be used iff
     obj['%data_key_name'] is not set or empty. Assumption is file content is
     raw data and data field is base64 string. The assumption can be changed
     with base64_file_content flag. If set to False, the content of the file
     will assumed to be base64 and read as is. The default True value will
     result in base64 encode of the file content after read."""

    def __init__(self, obj, file_key_name, data_key_name=None,
                 file_base_path="", base64_file_content=True,
                 temp_file_path=None):
        if not data_key_name:
            data_key_name = file_key_name + "-data"
        self._file = None
        self._data = None
        self._base64_file_content = base64_file_content
        self._temp_file_path = temp_file_path
        if not obj:
            return
        if data_key_name in obj:
            self._data = obj[data_key_name]
        elif file_key_name in obj:
            self._file = os.path.normpath(
                os.path.join(file_base_path, obj[file_key_name]))

    def as_file(self):
        """If obj[%data_key_name] exists, return name of a file with base64
        decoded obj[%data_key_name] content otherwise obj[%file_key_name]."""
        use_data_if_no_file = not self._file and self._data
        if use_data_if_no_file:
            self._write_file()

            if self._file and not os.path.isfile(self._file):
                self._write_file(force_rewrite=True)
        if self._file and not os.path.isfile(self._file):
            raise ConfigException("File does not exist: %s" % self._file)
        return self._file

    def as_data(self):
        """If obj[%data_key_name] exists, Return obj[%data_key_name] otherwise
        base64 encoded string of obj[%file_key_name] file content."""
        use_file_if_no_data = not self._data and self._file
        if use_file_if_no_data:
            with open(self._file) as f:
                if self._base64_file_content:
                    self._data = bytes.decode(
                        base64.standard_b64encode(str.encode(f.read())))
                else:
                    self._data = f.read()
        return self._data

    def _write_file(self, force_rewrite=False):
        if self._base64_file_content:
            if isinstance(self._data, str):
                content = self._data.encode()
            else:
                content = self._data
            self._file = _create_temp_file_with_content(
                base64.standard_b64decode(content), self._temp_file_path, force_recreate=force_rewrite)
        else:
            self._file = _create_temp_file_with_content(
                self._data, self._temp_file_path, force_recreate=force_rewrite)


class CommandTokenSource:
    def __init__(self, cmd, args, tokenKey, expiryKey):
        self._cmd = cmd
        self._args = args
        if not tokenKey:
            self._tokenKey = '{.access_token}'
        else:
            self._tokenKey = tokenKey
        if not expiryKey:
            self._expiryKey = '{.token_expiry}'
        else:
            self._expiryKey = expiryKey

    def token(self):
        fullCmd = self._cmd + (" ") + " ".join(self._args)
        process = subprocess.Popen(
            [self._cmd] + self._args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True)
        (stdout, stderr) = process.communicate()
        exit_code = process.wait()
        if exit_code != 0:
            msg = 'cmd-path: process returned %d' % exit_code
            msg += "\nCmd: %s" % fullCmd
            stderr = stderr.strip()
            if stderr:
                msg += '\nStderr: %s' % stderr
            raise ConfigException(msg)
        try:
            data = json.loads(stdout)
        except ValueError as de:
            raise ConfigException(
                'exec: failed to decode process output: %s' % de)
        A = namedtuple('A', ['token', 'expiry'])
        return A(
            token=data['credential']['access_token'],
            expiry=parse_rfc3339(data['credential']['token_expiry']))


class KubeConfigLoader:

    def __init__(self, config_dict, active_context=None,
                 get_google_credentials=None,
                 config_base_path="",
                 config_persister=None,
                 temp_file_path=None,
                 source_policy=None,
                 audit=None):

        if config_dict is None:
            raise ConfigException(
                'Invalid kube-config. '
                'Expected config_dict to not be None.')
        elif isinstance(config_dict, ConfigNode):
            self._config = config_dict
        else:
            self._config = ConfigNode('kube-config', config_dict)

        self._config_base_path = config_base_path
        self._config_persister = config_persister
        self._temp_file_path = temp_file_path
        self.source_policy = source_policy
        self.audit = audit
        self.audit_record = None
        self._context_source = None
        self._user_source = None
        self._cluster_source = None
        self._current_context = None
        self._user = None
        self._cluster = None
        self.set_active_context(active_context)

        def _refresh_credentials_with_cmd_path():
            config = self._user['auth-provider']['config']
            cmd = config['cmd-path']
            if len(cmd) == 0:
                raise ConfigException(
                    'missing access token cmd '
                    '(cmd-path is an empty string in your kubeconfig file)')
            if 'scopes' in config and config['scopes'] != "":
                raise ConfigException(
                    'scopes can only be used '
                    'when kubectl is using a gcp service account key')
            args = []
            if 'cmd-args' in config:
                args = config['cmd-args'].split()
            else:
                fields = config['cmd-path'].split()
                cmd = fields[0]
                args = fields[1:]

            # ``cmd-path`` runs a local helper just like an exec plugin, so
            # it needs the same capability from the user's own source.
            self._check_source(self._user_source, CAPABILITY_EXEC, 'exec')
            record = self.audit_record
            if record is not None:
                record.exec_configured = True
                record.exec_command = [cmd] + list(args)
                record.exec_authorized = True
                record.exec_invocations += 1
            commandTokenSource = CommandTokenSource(
                cmd, args,
                config.safe_get('token-key'),
                config.safe_get('expiry-key'))
            return commandTokenSource.token()

        def _refresh_credentials():
            # Refresh credentials using cmd-path
            if ('auth-provider' in self._user and
                'config' in self._user['auth-provider'] and
                    'cmd-path' in self._user['auth-provider']['config']):
                return _refresh_credentials_with_cmd_path()
            
            # Make the Google auth block optional.
            if google_auth_available:
                credentials, project_id = google.auth.default(scopes=[
                    'https://www.googleapis.com/auth/cloud-platform',
                    'https://www.googleapis.com/auth/userinfo.email'
                ])
                request = google.auth.transport.requests.Request()
                credentials.refresh(request)
                return credentials
            else:
                return None
            
        if get_google_credentials:
            self._get_google_credentials = get_google_credentials
        else:
            self._get_google_credentials = _refresh_credentials

    def set_active_context(self, context_name=None):
        if context_name is None:
            context_name = self._config['current-context']
        self._current_context = self._config['contexts'].get_with_name(
            context_name)
        user_name = self._current_context['context'].safe_get('user')
        user_node = None
        if user_name and self._config.safe_get('users'):
            user_node = self._config['users'].get_with_name(
                user_name, safe=True)
        if user_node:
            self._user = user_node['user']
        else:
            self._user = None
        cluster_name = self._current_context['context']['cluster']
        cluster_node = self._config['clusters'].get_with_name(cluster_name)
        self._cluster = cluster_node['cluster']

        self._context_source = self._current_context.path
        self._user_source = (
            user_node.path if user_node is not None else None)
        self._cluster_source = cluster_node.path

        self.audit_record = KubeConfigAuditRecord(
            context_name=context_name,
            context_source=self._context_source,
            cluster_name=cluster_name,
            cluster_source=self._cluster_source,
            user_name=user_name if user_node is not None else None,
            user_source=self._user_source,
        )
        if self.audit is not None:
            self.audit.records.append(self.audit_record)

    def _check_source(self, source, capability, stage):
        """Enforce the source policy for one resolved config component.

        ``source`` is the path of the file the component was actually defined
        in, not the path of the file passed to the loader.  A merged context can
        borrow its cluster from one file and its user from another, so each
        component is checked independently.
        """
        record = self.audit_record
        if self.source_policy is None:
            return
        if record is not None:
            record.policy_enforced = True
            canonical = canonical_source_path(source)
            record.source_capabilities[canonical] = \
                self.source_policy.capabilities_for(source)
        try:
            self.source_policy.check(source, capability, stage)
        except KubeConfigSourceError as error:
            if record is not None:
                record.decision = 'denied'
                record.denied_capability = error.capability
                record.denied_stage = error.stage
                record.denied_source = error.source
                record.error = str(error)
            raise

    def authorize_sources(self):
        """Validate the resolved context against the source policy.

        This runs before any authentication work so that an unapproved source
        can never cause an authentication plugin to be spawned, even when the
        context entry itself lives in an approved file.
        """
        if self.source_policy is None:
            return
        self._check_source(
            self._context_source, CAPABILITY_DESCRIBE, 'context')
        self._check_source(
            self._cluster_source, CAPABILITY_DESCRIBE, 'cluster')
        if self._user is not None:
            self._check_source(
                self._user_source, CAPABILITY_AUTHENTICATE, 'user')
            if 'exec' in self._user:
                self._check_source(
                    self._user_source, CAPABILITY_EXEC, 'exec')

    def _record_source_materials(self):
        record = self.audit_record
        if record is None:
            return
        cluster = self._cluster.value
        user = self._user.value if self._user is not None else {}
        record.certificate_authority = _describe_material_field(
            cluster, 'certificate-authority',
            getattr(self, 'ssl_ca_cert', None))
        origin = getattr(self, '_material_origin', None)
        record.client_certificate = _describe_material_field(
            user, 'client-certificate',
            getattr(self, 'cert_file', None), origin=origin)
        record.client_key = _describe_material_field(
            user, 'client-key',
            getattr(self, 'key_file', None), origin=origin)

    def _load_authentication(self):
        """Read authentication from kube-config user section if exists.

        This function goes through various authentication methods in user
        section of kube-config and stops if it finds a valid authentication
        method. The order of authentication methods is:

            1. auth-provider (gcp, azure, oidc)
            2. token field (point to a token file)
            3. exec provided plugin
            4. username/password

        The resolved cluster and user sources are checked against the source
        policy on every call, so a token refresh cannot re-use an approval
        that has since been withdrawn for one of the contributing files.
        """
        self.authorize_sources()
        if not self._user:
            return
        if self._load_auth_provider_token():
            return
        if self._load_user_token():
            return
        if self._load_from_exec_plugin():
            return
        self._load_user_pass_token()

    def _load_auth_provider_token(self):
        if 'auth-provider' not in self._user:
            return
        provider = self._user['auth-provider']
        if 'name' not in provider:
            return
        if provider['name'] == 'gcp':
            return self._load_gcp_token(provider)
        if provider['name'] == 'oidc':
            return self._load_oid_token(provider)



    def _record_identity(self, method, **fields):
        record = self.audit_record
        if record is None:
            return
        identity = {'method': method}
        identity.update(fields)
        record.identity = identity

    def _load_gcp_token(self, provider):
        if (('config' not in provider) or
                ('access-token' not in provider['config']) or
                ('expiry' in provider['config'] and
                 _is_expired(provider['config']['expiry']))):
            # token is not available or expired, refresh it
            self._refresh_gcp_token()

        self.token = "Bearer %s" % provider['config']['access-token']
        self._record_identity('gcp-auth-provider')
        if 'expiry' in provider['config']:
            self.expiry = parse_rfc3339(provider['config']['expiry'])
        return self.token

    def _refresh_gcp_token(self):
        if 'config' not in self._user['auth-provider']:
            self._user['auth-provider'].value['config'] = {}
        provider = self._user['auth-provider']['config']
        credentials = self._get_google_credentials()
        provider.value['access-token'] = credentials.token
        provider.value['expiry'] = format_rfc3339(credentials.expiry)
        if self._config_persister:
            self._config_persister()

    def _load_oid_token(self, provider):
        if 'config' not in provider:
            return

        reserved_characters = frozenset(["=", "+", "/"])
        token = provider['config']['id-token']

        if any(char in token for char in reserved_characters):
            # Invalid jwt, as it contains url-unsafe chars
            return

        parts = token.split('.')
        if len(parts) != 3:  # Not a valid JWT
            return

        padding = (4 - len(parts[1]) % 4) * '='
        if len(padding) == 3:
            # According to spec, 3 padding characters cannot occur
            # in a valid jwt
            # https://tools.ietf.org/html/rfc7515#appendix-C
            return

        jwt_attributes = json.loads(
            base64.urlsafe_b64decode(parts[1] + padding).decode('utf-8')
        )

        expire = jwt_attributes.get('exp')

        if ((expire is not None) and
            (_is_expired(datetime.datetime.fromtimestamp(expire,
                                                         tz=UTC)))):
            self._refresh_oidc(provider)

            if self._config_persister:
                self._config_persister()

        self.token = "Bearer %s" % provider['config']['id-token']
        self._record_identity('oidc-auth-provider')

        return self.token

    def _refresh_oidc(self, provider):
        config = Configuration()

        if 'idp-certificate-authority-data' in provider['config']:
            cert = base64.b64decode(
                provider['config']['idp-certificate-authority-data']
            ).decode('utf-8')

            # Use the shared temp-file helper instead of reopening a
            # NamedTemporaryFile by name, which fails with PermissionError
            # on Windows while the original handle is still open.
            config.ssl_ca_cert = _create_temp_file_with_content(cert)

        elif 'idp-certificate-authority' in provider['config']:
            config.ssl_ca_cert = provider['config']['idp-certificate-authority']

        else:
            config.verify_ssl = False

        client = ApiClient(configuration=config)

        response = client.call_api(
            method="GET",
            url="%s/.well-known/openid-configuration"
            % provider['config']['idp-issuer-url']
        )
        response.read()

        if response.status != 200:
            return

        response = json.loads(response.data)

        request = OAuth2Session(
            client_id=provider['config']['client-id'],
            token=provider['config']['refresh-token'],
            auto_refresh_kwargs={
                'client_id': provider['config']['client-id'],
                'client_secret': provider['config']['client-secret']
            },
            auto_refresh_url=response['token_endpoint']
        )

        try:
            refresh = request.refresh_token(
                token_url=response['token_endpoint'],
                refresh_token=provider['config']['refresh-token'],
                auth=(provider['config']['client-id'],
                      provider['config']['client-secret']),
                verify=config.ssl_ca_cert if config.verify_ssl else None
            )
        except oauthlib.oauth2.rfc6749.errors.InvalidClientIdError:
            return

        provider['config'].value['id-token'] = refresh['id_token']
        provider['config'].value['refresh-token'] = refresh['refresh_token']

    def _load_from_exec_plugin(self):
        if 'exec' not in self._user:
            return
        try:
            # The exec block belongs to the user entry; in a merged config its
            # relative paths resolve against the user's file, not the
            # cluster's.
            base_path = self._get_base_path(self._user.path)
            # The capability check on the context is not enough on its own:
            # the user entry itself has to come from a file that is approved
            # to run authentication plugins.  This is re-checked every time,
            # including token refreshes.
            self._check_source(self._user_source, CAPABILITY_EXEC, 'exec')
            exec_config = self._user['exec']
            command = [exec_config['command']]
            if exec_config.safe_get('args'):
                command.extend(exec_config['args'])
            record = self.audit_record
            if record is not None:
                record.exec_configured = True
                record.exec_command = list(command)
                record.exec_authorized = False

            def _count_execution():
                if record is not None:
                    record.exec_authorized = True
                    record.exec_invocations += 1

            status = ExecProvider(
                exec_config, base_path, self._cluster,
                authorize=lambda: self._check_source(
                    self._user_source, CAPABILITY_EXEC, 'exec'),
                on_execute=_count_execution).run()
            if 'token' in status:
                self.token = "Bearer %s" % status['token']
            elif 'clientCertificateData' in status:
                # https://kubernetes.io/docs/reference/access-authn-authz/authentication/#input-and-output-formats
                # Plugin has provided certificates instead of a token.
                if 'clientKeyData' not in status:
                    logging.error('exec: missing clientKeyData field in '
                                  'plugin output')
                    return None
                self.cert_file = FileOrData(
                    status, None,
                    data_key_name='clientCertificateData',
                    file_base_path=base_path,
                    base64_file_content=False,
                    temp_file_path=self._temp_file_path).as_file()
                self.key_file = FileOrData(
                    status, None,
                    data_key_name='clientKeyData',
                    file_base_path=base_path,
                    base64_file_content=False,
                    temp_file_path=self._temp_file_path).as_file()
                self._material_origin = 'exec-plugin'
            else:
                logging.error('exec: missing token or clientCertificateData '
                              'field in plugin output')
                return None
            if 'expirationTimestamp' in status:
                self.expiry = parse_rfc3339(status['expirationTimestamp'])
            if self.audit_record is not None:
                self.audit_record.exec_succeeded = True
            if 'token' in status:
                self._record_identity(
                    'exec-plugin-token',
                    exec_command=list(self.audit_record.exec_command)
                    if self.audit_record is not None else None)
            else:
                self._record_identity(
                    'exec-plugin-certificate',
                    exec_command=list(self.audit_record.exec_command)
                    if self.audit_record is not None else None)
            return True
        except KubeConfigSourceError:
            # A denied source must fail the load, not fall through to another
            # authentication method.
            raise
        except Exception as e:
            logging.error(str(e))

    def _load_user_token(self):
        base_path = self._get_base_path(self._user.path)
        token = FileOrData(
            self._user, 'tokenFile', 'token',
            file_base_path=base_path,
            base64_file_content=False,
            temp_file_path=self._temp_file_path).as_data()
        if token:
            self.token = "Bearer %s" % token
            self._record_identity('token')
            return True

    def _load_user_pass_token(self):
        if 'username' in self._user and 'password' in self._user:
            self.token = urllib3.util.make_headers(
                basic_auth=(self._user['username'] + ':' +
                            self._user['password'])).get('authorization')
            self._record_identity('basic-auth')
            return True

    def _get_base_path(self, config_path):
        if self._config_base_path is not None:
            return self._config_base_path
        if config_path is not None:
            return os.path.abspath(os.path.dirname(config_path))
        return ""

    def _load_cluster_info(self):
        if self.audit_record is not None:
            self.audit_record.server = self._cluster.safe_get('server')
        if 'server' in self._cluster:
            self.host = self._cluster['server'].rstrip('/')
            if self.host.startswith("https"):
                base_path = self._get_base_path(self._cluster.path)
                self.ssl_ca_cert = FileOrData(
                    self._cluster, 'certificate-authority',
                    file_base_path=base_path,
                    temp_file_path=self._temp_file_path).as_file()
                if 'cert_file' not in self.__dict__:
                    # cert_file could have been provided by
                    # _load_from_exec_plugin; only load from the _user
                    # section if we need it.  These paths belong to the user
                    # entry, which in a merged config may live in a different
                    # file than the cluster, so resolve them against the
                    # user's own source.
                    user_base_path = self._get_base_path(
                        self._user.path if self._user is not None else None)
                    self.cert_file = FileOrData(
                        self._user, 'client-certificate',
                        file_base_path=user_base_path,
                        temp_file_path=self._temp_file_path).as_file()
                    self.key_file = FileOrData(
                        self._user, 'client-key',
                        file_base_path=user_base_path,
                        temp_file_path=self._temp_file_path).as_file()
        if 'insecure-skip-tls-verify' in self._cluster:
            self.verify_ssl = not self._cluster['insecure-skip-tls-verify']
        if self.audit_record is not None:
            self.audit_record.verify_ssl = getattr(
                self, 'verify_ssl', None)
        if 'tls-server-name' in self._cluster:
            self.tls_server_name = self._cluster['tls-server-name']
        if 'proxy-url' in self._cluster:
            self.proxy = self._cluster['proxy-url']

    def _set_config(self, client_configuration):
        if 'token' in self.__dict__:
            client_configuration.api_key['BearerToken'] = self.token

            def _refresh_api_key(client_configuration):
                if ('expiry' in self.__dict__ and _is_expired(self.expiry)):
                    self._load_authentication()
                self._set_config(client_configuration)
            client_configuration.refresh_api_key_hook = _refresh_api_key
        # copy these keys directly from self to configuration object
        keys = ['host', 'ssl_ca_cert', 'cert_file', 'key_file', 'verify_ssl',
                'tls_server_name', 'proxy']
        for key in keys:
            if key in self.__dict__:
                setattr(client_configuration, key, getattr(self, key))

    def load_and_set(self, client_configuration):
        try:
            self._load_authentication()
            self._load_cluster_info()
        except KubeConfigSourceError:
            raise
        except Exception as error:
            if self.audit_record is not None:
                self.audit_record.error = str(error)
            raise
        self._record_source_materials()
        self._set_config(client_configuration)

    def list_contexts(self):
        return [context.value for context in self._config['contexts']]

    @property
    def current_context(self):
        return self._current_context.value


class ConfigNode:
    """Remembers each config key's path and construct a relevant exception
    message in case of missing keys. The assumption is all access keys are
    present in a well-formed kube-config."""

    def __init__(self, name, value, path=None):
        self.name = name
        self.value = value
        self.path = path

    def __contains__(self, key):
        return key in self.value

    def __len__(self):
        return len(self.value)

    def safe_get(self, key):
        if (isinstance(self.value, list) and isinstance(key, int) or
                key in self.value):
            return self.value[key]

    def __getitem__(self, key):
        v = self.safe_get(key)
        if v is None:
            raise ConfigException(
                'Invalid kube-config file. Expected key %s in %s'
                % (key, self.name))
        if isinstance(v, dict) or isinstance(v, list):
            return ConfigNode('%s/%s' % (self.name, key), v, self.path)
        else:
            return v

    def get_with_name(self, name, safe=False):
        if not isinstance(self.value, list):
            raise ConfigException(
                'Invalid kube-config file. Expected %s to be a list'
                % self.name)
        result = None
        for v in self.value:
            if 'name' not in v:
                raise ConfigException(
                    'Invalid kube-config file. '
                    'Expected all values in %s list to have \'name\' key'
                    % self.name)
            if v['name'] == name:
                if result is None:
                    result = v
                else:
                    raise ConfigException(
                        'Invalid kube-config file. '
                        'Expected only one object with name %s in %s list'
                        % (name, self.name))
        if result is not None:
            if isinstance(result, ConfigNode):
                return result
            else:
                return ConfigNode(
                    '%s[name=%s]' %
                    (self.name, name), result, self.path)
        if safe:
            return None
        raise ConfigException(
            'Invalid kube-config file. '
            'Expected object with name %s in %s list' % (name, self.name))


class KubeConfigMerger:

    """Reads and merges configuration from one or more kube-config's.
    The property `config` can be passed to the KubeConfigLoader as config_dict.

    It uses a path attribute from ConfigNode to store the path to kubeconfig.
    This path is required to load certs from relative paths.

    A method `save_changes` updates changed kubeconfig's (it compares current
    state of dicts with).
    """

    def __init__(self, paths):
        self.paths = []
        self.config_files = {}
        self.config_merged = None
        if hasattr(paths, 'read'):
            self._load_config_from_file_like_object(paths)
        else:
            self._load_config_from_file_path(paths)

    @property
    def config(self):
        return self.config_merged

    def _load_config_from_file_like_object(self, string):
        if hasattr(string, 'getvalue'):
            config = yaml.safe_load(string.getvalue())
        else:
            config = yaml.safe_load(string.read())

        if config is None:
            raise ConfigException(
                'Invalid kube-config.')
        if self.config_merged is None:
            self.config_merged = copy.deepcopy(config)
        # doesn't need to do any further merging

    def _load_config_from_file_path(self, string):
        for path in string.split(ENV_KUBECONFIG_PATH_SEPARATOR):
            if path:
                path = os.path.expanduser(path)
                if os.path.exists(path):
                    self.paths.append(path)
                    self.load_config(path)
        self.config_saved = copy.deepcopy(self.config_files)

    def load_config(self, path):
        with open(path) as f:
            config = yaml.safe_load(f)

        if config is None:
            raise ConfigException(
                'Invalid kube-config. '
                '%s file is empty' % path)

        if self.config_merged is None:
            config_merged = copy.deepcopy(config)
            for item in ('clusters', 'contexts', 'users'):
                config_merged[item] = []
            self.config_merged = ConfigNode(path, config_merged, path)
        for item in ('clusters', 'contexts', 'users'):
            self._merge(item, config.get(item, []) or [], path)

        if 'current-context' in config:
            self.config_merged.value['current-context'] = config['current-context']

        self.config_files[path] = config

    def _merge(self, item, add_cfg, path):
        for new_item in add_cfg:
            for exists in self.config_merged.value[item]:
                if exists['name'] == new_item['name']:
                    break
            else:
                self.config_merged.value[item].append(ConfigNode(
                    '{}/{}'.format(path, new_item), new_item, path))

    def save_changes(self):
        for path in self.paths:
            if self.config_saved[path] != self.config_files[path]:
                self.save_config(path)
        self.config_saved = copy.deepcopy(self.config_files)

    def save_config(self, path):
        with open(path, 'w') as f:
            yaml.safe_dump(self.config_files[path], f,
                           default_flow_style=False)


def _get_kube_config_loader_for_yaml_file(
        filename, persist_config=False, **kwargs):
    return _get_kube_config_loader(
        filename=filename,
        persist_config=persist_config,
        **kwargs)


def _get_kube_config_loader(
        filename=None,
        config_dict=None,
        persist_config=False,
        source_policy=None,
        audit=None,
        **kwargs):
    if config_dict is None:
        kcfg = KubeConfigMerger(filename)
        if persist_config and 'config_persister' not in kwargs:
            kwargs['config_persister'] = kcfg.save_changes

        if kcfg.config is None:
            raise ConfigException(
                'Invalid kube-config file. '
                'No configuration found.')
        return KubeConfigLoader(
            config_dict=kcfg.config,
            config_base_path=None,
            source_policy=source_policy,
            audit=audit,
            **kwargs)
    else:
        return KubeConfigLoader(
            config_dict=config_dict,
            config_base_path=None,
            source_policy=source_policy,
            audit=audit,
            **kwargs)


def list_kube_config_contexts(config_file=None, source_policy=None):

    if config_file is None:
        config_file = KUBE_CONFIG_DEFAULT_LOCATION

    loader = _get_kube_config_loader(
        filename=config_file, source_policy=source_policy)
    return loader.list_contexts(), loader.current_context


def load_kube_config(config_file=None, context=None,
                     client_configuration=None,
                     persist_config=True,
                     temp_file_path=None,
                     source_policy=None,
                     audit=None):
    """Loads authentication and cluster information from kube-config file
    and stores them in kubernetes.client.configuration.

    :param config_file: Name of the kube-config file.
    :param context: set the active context. If is set to None, current_context
        from config file will be used.
    :param client_configuration: The kubernetes.client.Configuration to
        set configs to.
    :param persist_config: If True, config file will be updated when changed
        (e.g GCP token refresh).
    :param temp_file_path: store temp files path.
    :param source_policy: optional KubeConfigSourcePolicy limiting which
        kubeconfig files may contribute cluster descriptions, user
        credentials or exec plugin definitions.  Because merged configs draw
        these from different files, the policy is applied to each resolved
        component rather than to the entry config_file only.
    :param audit: optional KubeConfigAudit that receives a record describing
        the sources, certificates and identity actually used.
    """

    if config_file is None:
        config_file = KUBE_CONFIG_DEFAULT_LOCATION

    loader = _get_kube_config_loader(
        filename=config_file, active_context=context,
        persist_config=persist_config,
        temp_file_path=temp_file_path,
        source_policy=source_policy,
        audit=audit)

    if client_configuration is None:
        config = type.__call__(Configuration)
        loader.load_and_set(config)
        Configuration.set_default(config)
    else:
        loader.load_and_set(client_configuration)


def load_kube_config_from_dict(config_dict, context=None,
                               client_configuration=None,
                               persist_config=True,
                               temp_file_path=None,
                               source_policy=None,
                               audit=None):
    """Loads authentication and cluster information from config_dict file
    and stores them in kubernetes.client.configuration.

    :param config_dict: Takes the config file as a dict.
    :param context: set the active context. If is set to None, current_context
        from config file will be used.
    :param client_configuration: The kubernetes.client.Configuration to
        set configs to.
    :param persist_config: If True, config file will be updated when changed
        (e.g GCP token refresh).
    :param temp_file_path: store temp files path.
    :param source_policy: optional KubeConfigSourcePolicy.  A dict-based
        config has no file provenance, so a strict policy will treat its
        components as unverifiable.
    :param audit: optional KubeConfigAudit that receives a record describing
        the sources, certificates and identity actually used.
    """
    if config_dict is None:
        raise ConfigException(
            'Invalid kube-config dict. '
            'No configuration found.')

    loader = _get_kube_config_loader(
        config_dict=config_dict, active_context=context,
        persist_config=persist_config,
        temp_file_path=temp_file_path,
        source_policy=source_policy,
        audit=audit)

    if client_configuration is None:
        config = type.__call__(Configuration)
        loader.load_and_set(config)
        Configuration.set_default(config)
    else:
        loader.load_and_set(client_configuration)


def new_client_from_config(
        config_file=None,
        context=None,
        persist_config=True,
        client_configuration=None,
        source_policy=None,
        audit=None):
    """
    Loads configuration the same as load_kube_config but returns an ApiClient
    to be used with any API object. This will allow the caller to concurrently
    talk with multiple clusters.
    """
    if client_configuration is None:
        client_configuration = type.__call__(Configuration)
    load_kube_config(config_file=config_file, context=context,
                     client_configuration=client_configuration,
                     persist_config=persist_config,
                     source_policy=source_policy, audit=audit)
    return ApiClient(configuration=client_configuration)


def new_client_from_config_dict(
        config_dict=None,
        context=None,
        persist_config=True,
        temp_file_path=None,
        client_configuration=None,
        source_policy=None,
        audit=None):
    """
    Loads configuration the same as load_kube_config_from_dict but returns an ApiClient
    to be used with any API object. This will allow the caller to concurrently
    talk with multiple clusters.
    """
    if client_configuration is None:
        client_configuration = type.__call__(Configuration)
    load_kube_config_from_dict(config_dict=config_dict, context=context,
                               client_configuration=client_configuration,
                               persist_config=persist_config,
                               temp_file_path=temp_file_path,
                               source_policy=source_policy,
                               audit=audit)
    return ApiClient(configuration=client_configuration)
