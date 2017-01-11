# Copyright 2016 Juniper Networks. All rights reserved.
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

import requests
import time
import uuid

from cfgm_common import exceptions as vnc_exc
from vnc_api import vnc_api

from networking_bgpvpn.neutron.extensions import bgpvpn as bgpvpn_ext
from networking_bgpvpn.neutron.services.service_drivers import driver_api\
    as bgpvpn_driver_api
from networking_bgpvpn.neutron.services.common import utils as bgpvpn_utils
from neutron.common.config import cfg
from neutron_lib import exceptions as neutron_exc
from neutron.extensions import l3 as neutron_l3_ext
from oslo_log import log as logging

CONTRAIL_BGPVPN_DRIVER_NAME = 'Contrail'

LOG = logging.getLogger(__name__)


class ContrailBGPVPNDriver(bgpvpn_driver_api.BGPVPNDriverBase):
    """BGP VPN Service Driver class for Contrail SDN controller."""

    def __init__(self, service_plugin):
        super(ContrailBGPVPNDriver, self).__init__(service_plugin)
        LOG.debug("ContrailBGPVPNDriver service_plugin : %s", service_plugin)
        self._vnc_lib = None
        self.connected = self._connect_to_vnc_server()

    def _connect_to_vnc_server(self):
        admin_user = cfg.CONF.keystone_authtoken.admin_user
        admin_password = cfg.CONF.keystone_authtoken.admin_password
        admin_tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
        api_srvr_ip = cfg.CONF.APISERVER.api_server_ip
        api_srvr_port = cfg.CONF.APISERVER.api_server_port
        try:
            auth_host = cfg.CONF.keystone_authtoken.auth_host
        except cfg.NoSuchOptError:
            auth_host = "127.0.0.1"

        try:
            auth_protocol = cfg.CONF.keystone_authtoken.auth_protocol
        except cfg.NoSuchOptError:
            auth_protocol = "http"

        try:
            auth_port = cfg.CONF.keystone_authtoken.auth_port
        except cfg.NoSuchOptError:
            auth_port = "35357"

        try:
            auth_url = cfg.CONF.keystone_authtoken.auth_url
        except cfg.NoSuchOptError:
            auth_url = "/v2.0/tokens"

        try:
            auth_type = cfg.CONF.auth_strategy
        except cfg.NoSuchOptError:
            auth_type = "keystone"

        try:
            api_server_url = cfg.CONF.APISERVER.api_server_url
        except cfg.NoSuchOptError:
            api_server_url = "/"

        try:
            auth_token_url = cfg.CONF.APISERVER.auth_token_url
        except cfg.NoSuchOptError:
            auth_token_url = None

        # Retry till a api-server is up
        connected = False
        while not connected:
            try:
                self._vnc_api = vnc_api.VncApi(
                    admin_user, admin_password, admin_tenant_name,
                    api_srvr_ip, api_srvr_port, api_server_url,
                    auth_host=auth_host, auth_port=auth_port,
                    auth_protocol=auth_protocol, auth_url=auth_url,
                    auth_type=auth_type, auth_token_url=auth_token_url)
                connected = True
            except requests.exceptions.RequestException:
                time.sleep(3)
        return True

    @staticmethod
    def _project_id_neutron_to_vnc(proj_id):
        return str(uuid.UUID(proj_id))

    @staticmethod
    def _project_id_vnc_to_neutron(proj_id):
        return proj_id.replace("-", "")

    def _project_read(self, proj_id=None, fq_name=None):
        if proj_id:
            proj_id = self._project_id_neutron_to_vnc(proj_id)
        try:
            return self._vnc_api.project_read(id=proj_id, fq_name=fq_name)
        except vnc_exc.NoIdError:
            raise neutron_exc.NotFound(proj_id)

    def _validate_project_ids(self, context, filters=None):
        if not context.is_admin:
            return [self._project_id_neutron_to_vnc(context.tenant)]

        if not filters.get('tenant_id'):
            return None

        project_ids = []
        for project_id in filters.get('tenant_id'):
            try:
                project_ids.append(self._project_id_neutron_to_vnc(project_id))
            except ValueError:
                continue

        return project_ids

    def _neutron_dict_to_bgpvpn(self, bgpvpn_obj, bgpvpn_dict):
        if 'name' in bgpvpn_dict:
            bgpvpn_obj.set_display_name(bgpvpn_dict['name'])

        if 'type' in bgpvpn_dict:
            bgpvpn_obj.set_bgpvpn_type(bgpvpn_dict['type'])

        if 'route_targets' in bgpvpn_dict:
            rt_list = vnc_api.RouteTargetList(['target:' + rt for rt in
                                               bgpvpn_dict['route_targets']])
            bgpvpn_obj.set_route_target_list(rt_list)

        if 'import_targets' in bgpvpn_dict:
            import_rt_list = vnc_api.RouteTargetList(
                ['target:' + rt for rt in bgpvpn_dict['import_targets']])
            bgpvpn_obj.set_import_route_target_list(import_rt_list)

        if 'export_targets' in bgpvpn_dict:
            export_rt_list = vnc_api.RouteTargetList(
                ['target:' + rt for rt in bgpvpn_dict['export_targets']])
            bgpvpn_obj.set_export_route_target_list(export_rt_list)

        return bgpvpn_obj

    @staticmethod
    def _get_route_target_list(rt_list):
        if rt_list is not None:
            return [rt[7:] for rt in rt_list.get_route_target()]
        return []

    @staticmethod
    def _get_refs(refs):
        if refs is not None:
            return [ref['uuid'] for ref in refs]
        return []

    def _bgpvpn_to_neutron_dict(self, bgpvpn_obj, fields=None):
        bgpvpn_dict = {
            'id': bgpvpn_obj.uuid,
            'tenant_id': self._project_id_vnc_to_neutron(
                bgpvpn_obj.parent_uuid),
            'name': bgpvpn_obj.display_name,
            'type': bgpvpn_obj.bgpvpn_type,
            'route_targets': self._get_route_target_list(
                bgpvpn_obj.get_route_target_list()),
            'import_targets': self._get_route_target_list(
                bgpvpn_obj.get_import_route_target_list()),
            'export_targets': self._get_route_target_list(
                bgpvpn_obj.get_export_route_target_list()),
            'route_distinguishers': [],
            'networks': self._get_refs(
                bgpvpn_obj.get_virtual_network_back_refs()),
            'routers': self._get_refs(
                bgpvpn_obj.get_logical_router_back_refs()),
        }
        return bgpvpn_utils.make_bgpvpn_dict(bgpvpn_dict, fields=fields)

    def _resource_create(self, resource_type, obj):
        create_method = getattr(self._vnc_api, resource_type + '_create')
        try:
            try:
                obj_uuid = create_method(obj)
            except vnc_exc.RefsExistError:
                obj.uuid = str(uuid.uuid4())
                obj.name += '-' + obj.uuid
                obj.fq_name[-1] += '-' + obj.uuid
                obj_uuid = create_method(obj)
        except (vnc_exc.PermissionDenied, vnc_exc.BadRequest) as e:
            neutron_exc.BadRequest(resource_type=resource_type, msg=str(e))
        except vnc_exc.OverQuota as e:
            neutron_exc.OverQuota(overs=[resource_type], msg=str(e))
        return obj_uuid

    def create_bgpvpn(self, context, bgpvpn):
        LOG.debug("create_bgpvpn called with: %s" % bgpvpn)

        # Does not support to set route distinguisher
        if 'route_distinguishers' in bgpvpn and bgpvpn['route_distinguishers']:
            raise bgpvpn_ext.BGPVPNRDNotSupported(
                driver=CONTRAIL_BGPVPN_DRIVER_NAME)

        project_obj = self._project_read(bgpvpn['tenant_id'])
        id_perms_obj = vnc_api.IdPermsType(enable=True)
        bgpvpn_obj = self._neutron_dict_to_bgpvpn(
            vnc_api.Bgpvpn(bgpvpn['name'], project_obj, id_perms=id_perms_obj),
            bgpvpn)
        self._resource_create('bgpvpn', bgpvpn_obj)
        return self._bgpvpn_to_neutron_dict(bgpvpn_obj)

    def get_bgpvpns(self, context, filters=None, fields=None):
        bgpvpns = []
        if 'name' in filters:
            filters['display_name'] = filters.pop('name')
        if 'type' in filters:
            filters['bgpvpn_type'] = filters.pop('type')
        try:
            for bgpvpn_obj in self._vnc_api.bgpvpns_list(
                    obj_uuids=filters.pop('id', None),
                    parent_id=self._validate_project_ids(context, filters),
                    detail=True,
                    filters=filters,
                    fields=fields):
                bgpvpn_dict = self._bgpvpn_to_neutron_dict(bgpvpn_obj)
                if bgpvpn_utils.filter_resource(bgpvpn_dict, filters):
                    bgpvpns.append(bgpvpn_dict)
        except vnc_exc.BadRequest as e:
            raise neutron_exc.BadRequest(resource='bgpvpn', msg=str(e))
        return bgpvpns

    def get_bgpvpn(self, context, id, fields=None):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=id, fields=fields)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=id)
        return self._bgpvpn_to_neutron_dict(bgpvpn_obj)

    def update_bgpvpn(self, context, id, bgpvpn):
        if 'route_distinguishers' in bgpvpn:
            raise bgpvpn_ext.BGPVPNRDNotSupported(
                driver=CONTRAIL_BGPVPN_DRIVER_NAME)
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=id)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=id)
        bgpvpn_obj = self._neutron_dict_to_bgpvpn(bgpvpn_obj, bgpvpn)
        try:
            self._vnc_api.bgpvpn_update(bgpvpn_obj)
        except vnc_exc.BadRequest as e:
            raise neutron_exc.BadRequest(resource='bgpvpn', msg=str(e))
        return self._bgpvpn_to_neutron_dict(bgpvpn_obj)

    def delete_bgpvpn(self, context, id):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(
                id=id, fields=['virtual_network_back_refs',
                               'logical_router_back_refs'])
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=id)

        for vn_ref in bgpvpn_obj.get_virtual_network_back_refs() or []:
            try:
                vn_obj = self._vnc_api.virtual_network_read(id=vn_ref['uuid'])
            except vnc_exc.NoIdError:
                continue
            vn_obj.del_bgpvpn(bgpvpn_obj)
            self._vnc_api.virtual_network_update(vn_obj)

        for lr_ref in bgpvpn_obj.get_logical_router_back_refs() or []:
            try:
                lr_obj = self._vnc_api.logical_router_read(id=lr_ref['uuid'])
            except vnc_exc.NoIdError:
                continue
            lr_obj.del_bgpvpn(bgpvpn_obj)
            self._vnc_api.logical_router_update(lr_obj)

        try:
            self._vnc_api.bgpvpn_delete(id=id)
        except (vnc_exc.RefsExistError, vnc_exc.BadRequest) as e:
            raise neutron_exc.BadRequest(resource='bgpvpn', msg=str(e))

    def create_net_assoc(self, context, bgpvpn_id, network_association):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=bgpvpn_id)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        net_id = network_association['network_id']
        try:
            vn_obj = self._vnc_api.virtual_network_read(id=net_id)
        except vnc_exc.NoIdError:
            raise neutron_exc.NetworkNotFound(net_id=net_id)
        vn_obj.add_bgpvpn(bgpvpn_obj)
        try:
            self._vnc_api.virtual_network_update(vn_obj)
        except vnc_exc.BadRequest as exc:
            raise neutron_exc.BadRequest(resource='network_association',
                                         msg=str(exc))
        # Use the network ID as association id
        network_association['id'] = net_id
        network_association['bgpvpn_id'] = bgpvpn_id
        network_association.pop('project_id', None)
        return bgpvpn_utils.make_net_assoc_dict(**network_association)

    def get_net_assoc(self, context, assoc_id, bgpvpn_id, fields=None):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(
                id=bgpvpn_id, fields=['virtual_network_back_refs'])
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        associated_networks = [
            vn_ref['uuid'] for vn_ref in
            bgpvpn_obj.get_virtual_network_back_refs() or []
        ]
        if assoc_id not in associated_networks:
            raise bgpvpn_ext.BGPVPNNetAssocNotFound(id=assoc_id,
                                                    bgpvpn_id=bgpvpn_id)
        return bgpvpn_utils.make_net_assoc_dict(
            assoc_id,
            bgpvpn_obj.parent_uuid.replace('-', ''),
            bgpvpn_id,
            assoc_id)

    def get_net_assocs(self, context, bgpvpn_id, filters=None, fields=None):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(
                id=bgpvpn_id, fields=['virtual_network_back_refs'])
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        bgpvpn_net_assocs = []
        for vn_ref in bgpvpn_obj.get_virtual_network_back_refs() or []:
            bgpvpn_net_assoc = bgpvpn_utils.make_net_assoc_dict(
                vn_ref['uuid'],
                bgpvpn_obj.parent_uuid.replace('-', ''),
                bgpvpn_id,
                vn_ref['uuid'],
                fields,
            )
            if bgpvpn_utils.filter_resource(bgpvpn_net_assoc, filters):
                bgpvpn_net_assocs.append(bgpvpn_net_assoc)
        return bgpvpn_net_assocs

    def delete_net_assoc(self, context, assoc_id, bgpvpn_id):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=bgpvpn_id)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        try:
            vn_obj = self._vnc_api.virtual_network_read(id=assoc_id)
        except vnc_exc.NoIdError:
            raise neutron_exc.NetworkNotFound(net_id=assoc_id)
        vn_obj.del_bgpvpn(bgpvpn_obj)
        try:
            self._vnc_api.virtual_network_update(vn_obj)
        except vnc_exc.BadRequest as exc:
            raise neutron_exc.BadRequest(resource='network_association',
                                         msg=str(exc))
        return bgpvpn_utils.make_net_assoc_dict(
            assoc_id,
            bgpvpn_obj.parent_uuid.replace('-', ''),
            bgpvpn_id,
            assoc_id,
        )

    def find_bgpvpns_for_network(self, context, network_id, bgpvpn_type=None):
        try:
            vn_obj = self._vnc_api.virtual_network_read(id=network_id,
                                                        fields=['bgpvpn_refs'])
        except vnc_exc.NoIdError:
            raise neutron_exc.NetworkNotFound(net_id=network_id)
        bgpvpn_ids = [bgpvpn_ref['uuid'] for bgpvpn_ref in
                      vn_obj.get_bgpvpn_refs() or []]
        filters = {}
        if bgpvpn_type is not None:
            filters['bgpvpn_type'] = bgpvpn_type
        bgpvpns = []
        for bgpvpn_obj in self._vnc_api.bgpvpns_list(obj_uuids=bgpvpn_ids,
                                                     detail=True,
                                                     filters=filters):
            bgpvpns.append(self._bgpvpn_to_neutron_dict(bgpvpn_obj))
        return bgpvpns

    def create_router_assoc(self, context, bgpvpn_id, router_association):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=bgpvpn_id)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        router_id = router_association['router_id']
        try:
            lr_obj = self._vnc_api.logical_router_read(id=router_id)
        except vnc_exc.NoIdError:
            raise neutron_l3_ext.RouterNotFound(router_id=router_id)
        lr_obj.add_bgpvpn(bgpvpn_obj)
        try:
            self._vnc_api.logical_router_update(lr_obj)
        except vnc_exc.BadRequest as exc:
            raise neutron_exc.BadRequest(resource='router_association',
                                         msg=str(exc))
        # Use the router ID as association id
        router_association['id'] = router_id
        router_association['bgpvpn_id'] = bgpvpn_id
        router_association.pop('project_id', None)
        return bgpvpn_utils.make_router_assoc_dict(**router_association)

    def get_router_assoc(self, context, assoc_id, bgpvpn_id, fields=None):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(
                id=bgpvpn_id, fields=['logical_router_back_refs'])
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        associated_routers = [
            lr_ref['uuid'] for lr_ref in
            bgpvpn_obj.get_logical_router_back_refs() or []
        ]
        if assoc_id not in associated_routers:
            raise bgpvpn_ext.BGPVPNRouterAssocNotFound(id=assoc_id,
                                                       bgpvpn_id=bgpvpn_id)
        return bgpvpn_utils.make_router_assoc_dict(
            assoc_id,
            bgpvpn_obj.parent_uuid.replace('-', ''),
            bgpvpn_id,
            assoc_id)

    def get_router_assocs(self, context, bgpvpn_id, filters=None, fields=None):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(
                id=bgpvpn_id, fields=['logical_router_back_refs'])
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        bgpvpn_router_assocs = []
        for lr_ref in bgpvpn_obj.get_logical_router_back_refs() or []:
            bgpvpn_router_assoc = bgpvpn_utils.make_router_assoc_dict(
                lr_ref['uuid'],
                bgpvpn_obj.parent_uuid.replace('-', ''),
                bgpvpn_id,
                lr_ref['uuid'],
                fields,
            )
            if bgpvpn_utils.filter_resource(bgpvpn_router_assoc, filters):
                bgpvpn_router_assocs.append(bgpvpn_router_assoc)
        return bgpvpn_router_assocs

    def delete_router_assoc(self, context, assoc_id, bgpvpn_id):
        try:
            bgpvpn_obj = self._vnc_api.bgpvpn_read(id=bgpvpn_id)
        except vnc_exc.NoIdError:
            raise bgpvpn_ext.BGPVPNNotFound(id=bgpvpn_id)
        try:
            lr_obj = self._vnc_api.logical_router_read(id=assoc_id)
        except vnc_exc.NoIdError:
            raise neutron_l3_ext.RouterNotFound(router_id=assoc_id)
        lr_obj.del_bgpvpn(bgpvpn_obj)
        try:
            self._vnc_api.logical_router_update(lr_obj)
        except vnc_exc.BadRequest as exc:
            raise neutron_exc.BadRequest(resource='router_association',
                                         msg=str(exc))
        return bgpvpn_utils.make_router_assoc_dict(
            assoc_id,
            bgpvpn_obj.parent_uuid.replace('-', ''),
            bgpvpn_id,
            assoc_id,
        )

    def find_bgpvpns_for_router(self, context, router_id):
        try:
            lr_obj = self._vnc_api.logical_router_read(id=router_id,
                                                       fields=['bgpvpn_refs'])
        except vnc_exc.NoIdError:
            raise neutron_l3_ext.RouterNotFound(router_id=router_id)
        bgpvpn_ids = [bgpvpn_ref['uuid'] for bgpvpn_ref in
                      lr_obj.get_bgpvpn_refs() or []]
        bgpvpns = []
        for bgpvpn_obj in self._vnc_api.bgpvpns_list(obj_uuids=bgpvpn_ids,
                                                     detail=True):
            bgpvpns.append(self._bgpvpn_to_neutron_dict(bgpvpn_obj))
        return bgpvpns
