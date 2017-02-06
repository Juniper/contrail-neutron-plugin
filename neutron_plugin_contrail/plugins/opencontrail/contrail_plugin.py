# Copyright 2014 Juniper Networks.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Hampapur Ajay, Praneet Bachheti, Rudra Rugge, Atul Moghe
import requests

try:
    from neutron.api.v2.attributes import ATTR_NOT_SPECIFIED
except:
    from neutron_lib.constants import ATTR_NOT_SPECIFIED
try:
    from neutron.common.exceptions import ServiceUnavailable
except ImportError:
    from neutron_lib.exceptions import ServiceUnavailable
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest
from neutron.common.config import cfg
from neutron.db import portbindings_base
from neutron.db import quota_db  # noqa
from neutron.extensions import allowedaddresspairs
from neutron.extensions import external_net
from neutron.extensions import l3
from neutron.extensions import portbindings
from neutron.extensions import securitygroup
from neutron import neutron_plugin_base_v2
try:
    from neutron.openstack.common import importutils
except ImportError:
    from oslo_utils import importutils

try:
    from neutron.openstack.common import jsonutils as json
except ImportError:
    from oslo_serialization import jsonutils as json

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

from simplejson import JSONDecodeError
from eventlet.greenthread import getcurrent

from contrail_plugin_base import HttpResponseError
import contrail_plugin_base as plugin_base
from cfgm_common import utils as cfgmutils

_DEFAULT_KS_CERT_BUNDLE="/tmp/keystonecertbundle.pem"
_DEFAULT_API_CERT_BUNDLE="/tmp/apiservercertbundle.pem"
_DEFAULT_SERVER_CONNECT="http"
_DEFAULT_SECURE_SERVER_CONNECT="https"

LOG = logging.getLogger(__name__)

vnc_opts = [
    cfg.StrOpt('api_server_ip', default='127.0.0.1',
               help='IP address to connect to VNC controller'),
    cfg.StrOpt('api_server_port', default='8082',
               help='Port to connect to VNC controller'),
    cfg.DictOpt('contrail_extensions', default={},
                help='Enable Contrail extensions(policy, ipam)'),
]

analytics_opts = [
    cfg.StrOpt('analytics_api_ip', default='127.0.0.1',
               help='IP address to connect to VNC collector'),
    cfg.StrOpt('analytics_api_port', default='8081',
               help='Port to connect to VNC collector'),
]

class InvalidContrailExtensionError(ServiceUnavailable):
    message = _("Invalid Contrail Extension: %(ext_name) %(ext_class)")

class NeutronPluginContrailCoreV2(plugin_base.NeutronPluginContrailCoreBase):

    PLUGIN_URL_PREFIX = '/neutron'

    def _build_auth_details(self):
        #keystone
        self._authn_token = None
        if cfg.CONF.auth_strategy == 'keystone':
            kcfg = cfg.CONF.keystone_authtoken
            body = '{"auth":{"passwordCredentials":{'
            body += ' "username": "%s",' % (kcfg.admin_user)
            body += ' "password": "%s"},' % (kcfg.admin_password)
            body += ' "tenantName":"%s"}}' % (kcfg.admin_tenant_name)

            self._authn_body = body
            self._authn_token = cfg.CONF.keystone_authtoken.admin_token
            try:
                auth_token_url = cfg.CONF.APISERVER.auth_token_url
            except cfg.NoSuchOptError:
                auth_token_url = None

            if auth_token_url:
                self._keystone_url = auth_token_url
            else:
                self._keystone_url = "%s://%s:%s%s" % (
                    cfg.CONF.keystone_authtoken.auth_protocol,
                    cfg.CONF.keystone_authtoken.auth_host,
                    cfg.CONF.keystone_authtoken.auth_port,
                    "/v2.0/tokens")

            #Keystone SSL Support
            self._ksinsecure=cfg.CONF.keystone_authtoken.insecure
            kscertfile=cfg.CONF.keystone_authtoken.certfile
            kskeyfile=cfg.CONF.keystone_authtoken.keyfile
            kscafile=cfg.CONF.keystone_authtoken.cafile

            self._use_ks_certs = False
            if (cfg.CONF.keystone_authtoken.auth_protocol ==
                    _DEFAULT_SECURE_SERVER_CONNECT and kscafile):
                certs = [kscafile]
                if kscertfile and kskeyfile:
                    certs = [kscertfile, kskeyfile, kscafile]
                self._kscertbundle = cfgmutils.getCertKeyCaBundle(
                        _DEFAULT_KS_CERT_BUNDLE,certs)
                self._use_ks_certs = True

        #API Server SSL support
        self._apiusessl=cfg.CONF.APISERVER.use_ssl
        self._apiinsecure=cfg.CONF.APISERVER.insecure
        apicertfile=cfg.CONF.APISERVER.certfile
        apikeyfile=cfg.CONF.APISERVER.keyfile
        apicafile=cfg.CONF.APISERVER.cafile

        if self._apiusessl:
            self._apiserverconnect=_DEFAULT_SECURE_SERVER_CONNECT
        else:
            self._apiserverconnect=_DEFAULT_SERVER_CONNECT

        self._use_api_certs = False
        if self._apiusessl and apicafile:
            certs = [apicafile]
            if apicertfile and apikeyfile:
                certs = [apicertfile, apikeyfile, apicafile]
            self._apicertbundle = cfgmutils.getCertKeyCaBundle(
                    _DEFAULT_API_CERT_BUNDLE,certs)
            self._use_api_certs = True


    def _request_api_server(self, url, data=None, headers=None):
        # Attempt to post to Api-Server
        if self._apiinsecure:
             response = requests.post(url, data=data, headers=headers,verify=False)
        elif not self._apiinsecure and self._use_api_certs:
             response = requests.post(url, data=data, headers=headers,verify=self._apicertbundle)
        else:
             response = requests.post(url, data=data, headers=headers)
        if (response.status_code == requests.codes.unauthorized):
            # Get token from keystone and save it for next request
            if self._ksinsecure:
               response = requests.post(self._keystone_url,
                                        data=self._authn_body,
                                        headers={'Content-type': 'application/json'},verify=False)
            elif not self._ksinsecure and self._use_ks_certs:
               response = requests.post(self._keystone_url,
                                        data=self._authn_body,
                                        headers={'Content-type': 'application/json'},verify=self._kscertbundle)
            else:
               response = requests.post(self._keystone_url,
                                        data=self._authn_body,
                                        headers={'Content-type': 'application/json'})
            if (response.status_code == requests.codes.ok):
                # plan is to re-issue original request with new token
                auth_headers = headers or {}
                authn_content = json.loads(response.text)
                self._authn_token = authn_content['access']['token']['id']
                auth_headers['X-AUTH-TOKEN'] = self._authn_token
                response = self._request_api_server(url, data, auth_headers)
            else:
                raise RuntimeError('Authentication Failure')
        return response

    def _request_api_server_authn(self, url, data=None, headers=None):
        # forward user token to API server for RBAC
        # token saved earlier in the pipeline
        try:
            auth_token = getcurrent().contrail_vars.token
        except AttributeError:
            auth_token = None

        authn_headers = headers or {}
        if auth_token or self._authn_token:
            authn_headers['X-AUTH-TOKEN'] = auth_token or self._authn_token
        response = self._request_api_server(url, data, headers=authn_headers)
        return response

    def _relay_request(self, url_path, data=None):
        """Send received request to api server."""

        url = "%s://%s:%s%s" % (self._apiserverconnect,
                                cfg.CONF.APISERVER.api_server_ip,
                                cfg.CONF.APISERVER.api_server_port,
                                url_path)

        return self._request_api_server_authn(
            url, data=data, headers={'Content-type': 'application/json'})

    def _request_backend(self, context, data_dict, obj_name, action):
        context_dict = self._encode_context(context, action, obj_name)
        data = json.dumps({'context': context_dict, 'data': data_dict})

        url_path = "%s/%s" % (self.PLUGIN_URL_PREFIX, obj_name)
        response = self._relay_request(url_path, data=data)
        try:
            return response.status_code, response.json()
        except JSONDecodeError:
            return response.status_code, {'message': response.content}

    def _encode_context(self, context, operation, apitype):
        cdict = {'user_id': getattr(context, 'user_id', ''),
                 'is_admin': getattr(context, 'is_admin', False),
                 'operation': operation,
                 'type': apitype,
                 'tenant_id': getattr(context, 'tenant_id', None)}
        if context.roles:
            cdict['roles'] = context.roles
        if context.tenant:
            cdict['tenant'] = context.tenant
        return cdict

    def _encode_resource(self, resource_id=None, resource=None, fields=None,
                         filters=None):
        # New OpenStack release replace the 'tenant' term by 'project' and
        # all tools which call OpenStack APIs also did the moved and use
        # 'project_id' instead of 'tenant_id' to query resources for a project
        if (filters is not None and 'project_id' in filters and
                'tenant_id' not in filters):
            filters['tenant_id'] = filters['project_id']
        resource_dict = {}
        if resource_id:
            resource_dict['id'] = resource_id
        if resource:
            resource_dict['resource'] = resource
        resource_dict['filters'] = filters
        resource_dict['fields'] = fields
        return resource_dict

    def _prune(self, resource_dict, fields):
        if fields:
            return dict(((key, item) for key, item in resource_dict.items()
                         if key in fields))
        return resource_dict

    def _transform_response(self, status_code, info=None, obj_name=None,
                            fields=None):
        if status_code == requests.codes.ok:
            if not isinstance(info, list):
                return self._prune(info, fields)
            else:
                return [self._prune(items, fields) for items in info]

        plugin_base._raise_contrail_error(info, obj_name)


    def _create_resource(self, res_type, context, res_data):
        """Create a resource in API server.

        This method encodes neutron model, and sends it to the
        contrail api server.
        """

        for key, value in res_data[res_type].items():
            if value == ATTR_NOT_SPECIFIED:
                del res_data[res_type][key]

        res_dict = self._encode_resource(resource=res_data[res_type])
        status_code, res_info = self._request_backend(context, res_dict,
                                                      res_type, 'CREATE')
        res_dicts = self._transform_response(status_code, info=res_info,
                                             obj_name=res_type)
        LOG.debug("create_%(res_type)s(): %(res_dicts)s",
                  {'res_type': res_type, 'res_dicts': res_dicts})

        return res_dicts

    def _get_resource(self, res_type, context, id, fields):
        """Get a resource from API server.

        This method gets a resource from the contrail api server
        """

        res_dict = self._encode_resource(resource_id=id, fields=fields)
        status_code, res_info = self._request_backend(context, res_dict,
                                                      res_type, 'READ')
        res_dicts = self._transform_response(status_code, info=res_info,
                                             fields=fields, obj_name=res_type)
        LOG.debug("get_%(res_type)s(): %(res_dicts)s",
                  {'res_type': res_type, 'res_dicts': res_dicts})

        return res_dicts

    def _update_resource(self, res_type, context, id, res_data):
        """Update a resource in API server.

        This method updates a resource in the contrail api server
        """

        res_dict = self._encode_resource(resource_id=id,
                                         resource=res_data[res_type])
        status_code, res_info = self._request_backend(context, res_dict,
                                                      res_type, 'UPDATE')
        res_dicts = self._transform_response(status_code, info=res_info,
                                             obj_name=res_type)
        LOG.debug("update_%(res_type)s(): %(res_dicts)s",
                  {'res_type': res_type, 'res_dicts': res_dicts})

        return res_dicts

    def _delete_resource(self, res_type, context, id):
        """Delete a resource in API server

        This method deletes a resource in the contrail api server
        """

        res_dict = self._encode_resource(resource_id=id)
        LOG.debug("delete_%(res_type)s(): %(id)s",
                  {'res_type': res_type, 'id': id})
        status_code, res_info = self._request_backend(context, res_dict,
                                                      res_type, 'DELETE')
        if status_code != requests.codes.ok:
            plugin_base._raise_contrail_error(info=res_info,
                                              obj_name=res_type)

    def _list_resource(self, res_type, context, filters, fields):
        res_dict = self._encode_resource(filters=filters, fields=fields)
        status_code, res_info = self._request_backend(context, res_dict,
                                                      res_type, 'READALL')
        res_dicts = self._transform_response(status_code, info=res_info,
                                             fields=fields, obj_name=res_type)
        LOG.debug(
            "get_%(res_type)s(): filters: %(filters)r data: %(res_dicts)r",
            {'res_type': res_type, 'filters': filters,
             'res_dicts': res_dicts})

        return res_dicts

    def _count_resource(self, res_type, context, filters):
        res_dict = self._encode_resource(filters=filters)
        status_code, res_count = self._request_backend(context, res_dict,
                                                       res_type, 'READCOUNT')
        LOG.debug("get_%(res_type)s_count(): %(res_count)r",
                  {'res_type': res_type, 'res_count': res_count})
        return res_count


    def add_router_interface(self, context, router_id, interface_info):
        """Add interface to a router."""

        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            if 'subnet_id' in interface_info:
                msg = _("Cannot specify both subnet-id and port-id")
                raise BadRequest(resource='router', msg=msg)

        res_dict = self._encode_resource(resource_id=router_id,
                                         resource=interface_info)
        status_code, res_info = self._request_backend(context, res_dict,
                                                      'router', 'ADDINTERFACE')
        if status_code != requests.codes.ok:
            plugin_base._raise_contrail_error(info=res_info,
                                              obj_name='add_router_interface')
        return res_info

    def remove_router_interface(self, context, router_id, interface_info):
        """Delete interface from a router."""

        if not interface_info:
            msg = _("Either subnet_id or port_id must be specified")
            raise BadRequest(resource='router', msg=msg)

        res_dict = self._encode_resource(resource_id=router_id,
                                         resource=interface_info)
        status_code, res_info = self._request_backend(context, res_dict,
                                                      'router', 'DELINTERFACE')
        if status_code != requests.codes.ok:
            plugin_base._raise_contrail_error(info=res_info,
                                              obj_name='remove_router_interface')
        return res_info
