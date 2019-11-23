# Copyright 2015.  All rights reserved.
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


try:
    from neutron.api.v2.attributes import ATTR_NOT_SPECIFIED
except Exception:
    from neutron_lib.constants import ATTR_NOT_SPECIFIED
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest
try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

from eventlet import greenthread

from neutron_plugin_contrail.common import utils
import neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_base as plugin_base

from neutron_plugin_contrail.plugins.opencontrail.vnc_client import fip_res_handler as fip_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import ipam_res_handler as ipam_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import policy_res_handler as policy_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import route_table_res_handler as route_table_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import router_res_handler as rtr_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import sg_res_handler as sg_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import sgrule_res_handler as sgrule_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import subnet_res_handler as subnet_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import svc_instance_res_handler as svc_instance_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import virtual_router_res_handler as vrouter_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import vmi_res_handler as vmi_handler
from neutron_plugin_contrail.plugins.opencontrail.vnc_client import vn_res_handler as vn_handler


LOG = logging.getLogger(__name__)


class NeutronPluginContrailCoreV3(plugin_base.NeutronPluginContrailCoreBase):

    PLUGIN_URL_PREFIX = '/neutron'

    def __init__(self):
        super(NeutronPluginContrailCoreV3, self).__init__()
        self._vnc_lib = None
        utils.register_vnc_api_extra_options()
        self._vnc_lib = utils.get_vnc_api_instance()
        self._res_handlers = {}
        self._prepare_res_handlers()
        self.api_servers = utils.RoundRobinApiServers()

    def _set_user_auth_token(self):
        api_server_list = self.api_servers.api_servers[:]
        api_server = self.api_servers.get(api_server_list)
        if not utils.vnc_api_is_authenticated(api_server):
            return

        # forward user token to API server for RBAC
        # token saved earlier in the pipeline
        try:
            auth_token = greenthread.getcurrent().contrail_vars.token
            self._vnc_lib.set_auth_token(auth_token)
        except AttributeError:
            pass

    def _prepare_res_handlers(self):
        contrail_extension_enabled = cfg.CONF.APISERVER.contrail_extensions
        apply_subnet_host_routes = cfg.CONF.APISERVER.apply_subnet_host_routes
        kwargs = {'contrail_extensions_enabled': contrail_extension_enabled,
                  'apply_subnet_host_routes': apply_subnet_host_routes}

        self._res_handlers['network'] = vn_handler.VNetworkHandler(
            self._vnc_lib, **kwargs)

        self._res_handlers['subnet'] = subnet_handler.SubnetHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['port'] = vmi_handler.VMInterfaceHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['router'] = rtr_handler.LogicalRouterHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['floatingip'] = fip_handler.FloatingIpHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['security_group'] = sg_handler.SecurityGroupHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['security_group_rule'] = (
            sgrule_handler.SecurityGroupRuleHandler(self._vnc_lib, **kwargs))

        self._res_handlers['ipam'] = ipam_handler.IPamHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['policy'] = policy_handler.PolicyHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['route_table'] = (
            route_table_handler.RouteTableHandler(self._vnc_lib, **kwargs))
        self._res_handlers['svc'] = svc_instance_handler.SvcInstanceHandler(
            self._vnc_lib, **kwargs)
        self._res_handlers['virtual_router'] = \
            vrouter_handler.VirtualRouterHandler(self._vnc_lib, **kwargs)

    def _get_context_dict(self, context):
        return dict(context.__dict__)

    def _create_resource(self, res_type, context, res_data):
        for key, value in res_data[res_type].items():
            if value == ATTR_NOT_SPECIFIED:
                del res_data[res_type][key]

        self._set_user_auth_token()
        return self._res_handlers[res_type].resource_create(
            self._get_context_dict(context), res_data[res_type])

    def _get_resource(self, res_type, context, id, fields):
        self._set_user_auth_token()
        return self._res_handlers[res_type].resource_get(
            self._get_context_dict(context), id, fields)

    def _update_resource(self, res_type, context, id, res_data):
        self._set_user_auth_token()
        return self._res_handlers[res_type].resource_update(
            self._get_context_dict(context), id, res_data[res_type])

    def _delete_resource(self, res_type, context, id):
        self._set_user_auth_token()
        return self._res_handlers[res_type].resource_delete(
            self._get_context_dict(context), id)

    def _list_resource(self, res_type, context, filters, fields):
        self._set_user_auth_token()
        return self._res_handlers[res_type].resource_list(
            self._get_context_dict(context), filters, fields)

    def _count_resource(self, res_type, context, filters):
        self._set_user_auth_token()
        res_count = self._res_handlers[res_type].resource_count(
            self._get_context_dict(context), filters)
        return {'count': res_count}

    def add_router_interface(self, context, router_id, interface_info):
        """Add interface to a router."""

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise BadRequest(resource='router', msg=msg)

        if 'port_id' in interface_info:
            if 'subnet_id' in interface_info:
                msg = "Cannot specify both subnet-id and port-id"
                raise BadRequest(resource='router', msg=msg)

        self._set_user_auth_token()
        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')

        rtr_iface_handler = rtr_handler.LogicalRouterInterfaceHandler(
            self._vnc_lib)
        return rtr_iface_handler.add_router_interface(
            self._get_context_dict(context), router_id,
            port_id=port_id, subnet_id=subnet_id)

    def remove_router_interface(self, context, router_id, interface_info):
        """Delete interface from a router."""

        if not interface_info:
            msg = "Either subnet_id or port_id must be specified"
            raise BadRequest(resource='router', msg=msg)

        port_id = interface_info.get('port_id')
        subnet_id = interface_info.get('subnet_id')

        self._set_user_auth_token()
        rtr_iface_handler = rtr_handler.LogicalRouterInterfaceHandler(
            self._vnc_lib)
        return rtr_iface_handler.remove_router_interface(
            self._get_context_dict(context), router_id, port_id=port_id,
            subnet_id=subnet_id)
