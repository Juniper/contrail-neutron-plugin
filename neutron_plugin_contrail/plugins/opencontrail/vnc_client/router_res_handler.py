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

from cfgm_common import exceptions as vnc_exc
import contrail_res_handler as res_handler
import netaddr
from neutron.common import constants as n_constants
import subnet_res_handler as subnet_handler
import vmi_res_handler as vmi_handler
from vnc_api import vnc_api


class LogicalRouterMixin(object):

    @staticmethod
    def _get_external_gateway_info(rtr_obj):
        vn_refs = rtr_obj.get_virtual_network_refs()
        if vn_refs:
            return vn_refs[0]['uuid']

    def _neutron_dict_to_rtr_obj(self, router_q, rtr_obj):
        rtr_name = router_q.get('name')
        id_perms = rtr_obj.get_id_perms()
        if 'admin_state_up' in router_q:
            id_perms.enable = router_q['admin_state_up']
            rtr_obj.set_id_perms(id_perms)

        if rtr_name:
            rtr_obj.display_name = rtr_name

        return rtr_obj

    def _rtr_obj_to_neutron_dict(self, rtr_obj,
                                 contrail_extensions_enabled=True,
                                 fields=None):
        rtr_q_dict = {}

        rtr_q_dict['id'] = rtr_obj.uuid
        if not rtr_obj.display_name:
            rtr_q_dict['name'] = rtr_obj.get_fq_name()[-1]
        else:
            rtr_q_dict['name'] = rtr_obj.display_name
        rtr_q_dict['tenant_id'] = self._project_id_vnc_to_neutron(
            rtr_obj.parent_uuid)
        rtr_q_dict['admin_state_up'] = rtr_obj.get_id_perms().enable
        rtr_q_dict['shared'] = False
        rtr_q_dict['status'] = n_constants.NET_STATUS_ACTIVE
        rtr_q_dict['gw_port_id'] = None

        ext_net_uuid = self._get_external_gateway_info(rtr_obj)
        if not ext_net_uuid:
            rtr_q_dict['external_gateway_info'] = None
        else:
            rtr_q_dict['external_gateway_info'] = {'network_id': ext_net_uuid,
                                                   'enable_snat': True}

        if contrail_extensions_enabled:
            rtr_q_dict.update({'contrail:fq_name': rtr_obj.get_fq_name()})

        if fields:
            rtr_q_dict = self._filter_res_dict(rtr_q_dict, fields)
        return rtr_q_dict

    def _router_update_gateway(self, router_q, rtr_obj):
        ext_gateway = router_q.get('external_gateway_info')
        old_ext_gateway = self._get_external_gateway_info(rtr_obj)
        if ext_gateway or old_ext_gateway:
            network_id = None
            if ext_gateway:
                network_id = ext_gateway.get('network_id')
            if network_id:
                if old_ext_gateway and network_id == old_ext_gateway:
                    return
                try:
                    vn_obj = self._vnc_lib.virtual_network_read(id=network_id)
                    if not vn_obj.get_router_external():
                        self._raise_contrail_exception(
                            'BadRequest', resource='router',
                            msg="Network %s is not a valid "
                                "external network" % network_id)
                except vnc_exc.NoIdError:
                    self._raise_contrail_exception('NetworkNotFound',
                                                   net_id=network_id)

                self._router_set_external_gateway(rtr_obj, vn_obj)
            else:
                self._router_clear_external_gateway(rtr_obj)

    def _router_set_external_gateway(self, router_obj, ext_net_obj):
        router_obj.set_virtual_network(ext_net_obj)
        self._vnc_lib.logical_router_update(router_obj)

    def _router_clear_external_gateway(self, router_obj):
        router_obj.set_virtual_network_list([])
        self._vnc_lib.logical_router_update(router_obj)


class LogicalRouterCreateHandler(res_handler.ResourceCreateHandler,
                                 LogicalRouterMixin):
    resource_create_method = 'logical_router_create'

    def _create_router(self, router_q):
        project_id = self._project_id_neutron_to_vnc(router_q['tenant_id'])
        project_obj = self._project_read(proj_id=project_id)
        id_perms = vnc_api.IdPermsType(enable=True)
        return vnc_api.LogicalRouter(router_q.get('name'), project_obj,
                                     id_perms=id_perms)

    def resource_create(self, context, router_q):
        rtr_obj = self._neutron_dict_to_rtr_obj(
            router_q, self._create_router(router_q))
        rtr_uuid = self._resource_create(rtr_obj)

        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        # read it back to update id perms
        rtr_obj = self._resource_get(id=rtr_uuid)
        self._router_update_gateway(router_q, rtr_obj)
        return self._rtr_obj_to_neutron_dict(
            rtr_obj, contrail_extensions_enabled=contrail_extensions_enabled)


class LogicalRouterDeleteHandler(res_handler.ResourceDeleteHandler,
                                 LogicalRouterMixin):
    resource_delete_method = 'logical_router_delete'

    def resource_delete(self, context, rtr_id):
        try:
            rtr_obj = self._resource_get(id=rtr_id)
            if rtr_obj.get_virtual_machine_interface_refs():
                self._raise_contrail_exception('RouterInUse',
                                               router_id=rtr_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception('RouterNotFound',
                                           router_id=rtr_id)

        self._router_clear_external_gateway(rtr_obj)
        try:
            self._resource_delete(id=rtr_id)
        except vnc_exc.RefsExistError:
            self._raise_contrail_exception('RouterInUse', router_id=rtr_id)


class LogicalRouterUpdateHandler(res_handler.ResourceUpdateHandler,
                                 LogicalRouterMixin):
    resource_update_method = 'logical_router_update'

    def _get_rtr_obj(self, router_q):
        return self._resource_get(id=router_q.get('id'))

    def resource_update(self, context, rtr_id, router_q):
        router_q['id'] = rtr_id
        rtr_obj = self._neutron_dict_to_rtr_obj(
            router_q, self._get_rtr_obj(router_q))
        self._resource_update(rtr_obj)
        self._router_update_gateway(router_q, rtr_obj)
        return self._rtr_obj_to_neutron_dict(rtr_obj)


class LogicalRouterGetHandler(res_handler.ResourceGetHandler,
                              LogicalRouterMixin):
    resource_get_method = 'logical_router_read'
    resource_list_method = 'logical_routers_list'

    def _router_list_project(self, project_id=None, detail=False):
        resp = self._resource_list(parent_id=project_id, detail=detail)
        if detail:
            return resp
        return resp['logical-routers']

    def _get_router_list_for_ids(self, rtr_ids, extensions_enabled=True):
        ret_list = []
        for rtr_id in rtr_ids or []:
            try:
                rtr_obj = self._resource_get(id=rtr_id)
                rtr_info = self._rtr_obj_to_neutron_dict(
                    rtr_obj,
                    contrail_extensions_enabled=extensions_enabled)
                ret_list.append(rtr_info)
            except vnc_exc.NoIdError:
                pass
        return ret_list

    def _get_router_list_for_project(self, project_id=None):
        project_rtrs = self._router_list_project(project_id=project_id)
        rtr_uuids = [rtr['uuid'] for rtr in project_rtrs]
        return self._get_router_list_for_ids(rtr_uuids)

    def _fip_pool_ref_routers(self, project_id):
        """TODO."""
        return []

    def get_vmi_obj_router_id(self, vmi_obj, project_id=None):
        vmi_get_handler = vmi_handler.VMInterfaceGetHandler(
            self._vnc_lib)

        port_net_id = vmi_obj.get_virtual_network_refs()[0]['uuid']
        # find router_id from port
        router_list = self._router_list_project(project_id=project_id,
                                                detail=True)
        for router_obj in router_list or []:
            for vmi in (router_obj.get_virtual_machine_interface_refs()
                        or []):
                vmi_obj = vmi_get_handler.get_vmi_obj(vmi['uuid'])
                if (vmi_obj.get_virtual_network_refs()[0]['uuid'] ==
                        port_net_id):
                    return router_obj.uuid

    def resource_get(self, context, rtr_uuid, fields=None):
        try:
            rtr_obj = self._resource_get(id=rtr_uuid)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception('RouterNotFound',
                                           router_id=rtr_uuid)

        return self._rtr_obj_to_neutron_dict(rtr_obj, fields=fields)

    def resource_list(self, context, filters, fields=None):
        extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        ret_list = []

        if filters and 'shared' in filters:
            if filters['shared'][0]:
                # no support for shared routers
                return ret_list

        if not filters:
            if context['is_admin']:
                return self._get_router_list_for_project()
            else:
                proj_id = self._project_id_neutron_to_vnc(context['tenant'])
                return self._get_router_list_for_project(project_id=proj_id)

        all_rtrs = []  # all n/ws in all projects
        if 'id' in filters:
            return self._get_router_list_for_ids(filters['id'],
                                                 extensions_enabled)

        if 'tenant_id' in filters:
            # read all routers in project, and prune below
            project_ids = self._validate_project_ids(
                context, project_ids=filters['tenant_id'])
            for p_id in project_ids:
                if 'router:external' in filters:
                    all_rtrs.append(self._fip_pool_ref_routers(p_id))
                else:
                    project_rtrs = self._router_list_project(p_id)
                    all_rtrs.append(project_rtrs)

        else:
            # read all routers in all projects
            project_rtrs = self._router_list_project()
            all_rtrs.append(project_rtrs)

        # prune phase
        for project_rtrs in all_rtrs:
            for proj_rtr in project_rtrs:
                proj_rtr_id = proj_rtr['uuid']
                if not self._filters_is_present(filters, 'id', proj_rtr_id):
                    continue

                proj_rtr_fq_name = unicode(proj_rtr['fq_name'])
                if not self._filters_is_present(filters, 'contrail:fq_name',
                                                proj_rtr_fq_name):
                    continue
                try:
                    rtr_obj = self._resource_get(id=proj_rtr['uuid'])
                    if not self._filters_is_present(
                            filters, 'name',
                            rtr_obj.get_display_name() or rtr_obj.name):
                        continue
                    rtr_info = self._rtr_obj_to_neutron_dict(
                        rtr_obj,
                        contrail_extensions_enabled=extensions_enabled,
                        fields=fields)
                    ret_list.append(rtr_info)
                except vnc_exc.NoIdError:
                    continue

        return ret_list

    def resource_count(self, context, filters=None):
        count = self._resource_count_optimized(filters)
        if count is not None:
            return count

        rtrs_info = self.router_list(filters=filters)
        return len(rtrs_info)


class LogicalRouterInterfaceHandler(res_handler.ResourceGetHandler,
                                    res_handler.ResourceUpdateHandler,
                                    LogicalRouterMixin):
    resource_get_method = 'logical_router_read'
    resource_list_method = 'logical_routers_list'
    resource_update_method = 'logical_router_update'

    def __init__(self, vnc_lib):
        super(LogicalRouterInterfaceHandler, self).__init__(vnc_lib)
        self._vmi_handler = vmi_handler.VMInterfaceHandler(
            self._vnc_lib)
        self._subnet_handler = subnet_handler.SubnetHandler(self._vnc_lib)

    def _get_subnet_cidr(self, subnet_id, subnet_dict):
        for subnet in subnet_dict:
            if subnet['id'] == subnet_id:
                return subnet['cidr']

    def _check_for_dup_router_subnet(self, router_obj, subnet_id,
                                     subnet_cidr):
        try:
            router_vmi_objs = []
            if router_obj.get_virtual_machine_interface_refs():
                vmis = [x['uuid']
                        for x in router_obj.virtual_machine_interface_refs]
                router_vmi_objs = self._vnc_lib.virtual_machine_interfaces_list(
                    obj_uuids=vmis, detail=True,
                    fields=['instance_ip_back_refs'])
            # It's possible router ports are on the same network, but
            # different subnets.
            new_ipnet = netaddr.IPNetwork(subnet_cidr)
            port_req_memo = {'virtual-machines': {},
                             'instance-ips': {},
                             'subnets': {}}
            for vmi_obj in router_vmi_objs:
                net_id = self._vmi_handler.get_vmi_net_id(vmi_obj)
                vn_obj = self._vnc_lib.virtual_network_read(id=net_id)

                fixed_ips = self._vmi_handler.get_vmi_ip_dict(vmi_obj, vn_obj,
                                                              port_req_memo)
                vn_subnets = (
                    subnet_handler.SubnetHandler.get_vn_subnets(
                        vn_obj))
                for ip in fixed_ips:
                    if ip['subnet_id'] == subnet_id:
                        msg = ("Router %s already has a port on subnet %s"
                               % (router_obj.uuid, subnet_id))
                        self._raise_contrail_exception(
                            'BadRequest', resource='router', msg=msg)
                    sub_id = ip['subnet_id']
                    cidr = self._get_subnet_cidr(sub_id, vn_subnets)
                    ipnet = netaddr.IPNetwork(cidr)
                    match1 = netaddr.all_matching_cidrs(new_ipnet, [cidr])
                    match2 = netaddr.all_matching_cidrs(ipnet, [subnet_cidr])
                    if match1 or match2:
                        data = {'subnet_cidr': subnet_cidr,
                                'subnet_id': subnet_id,
                                'cidr': cidr,
                                'sub_id': sub_id}
                        msg = (("Cidr %(subnet_cidr)s of subnet "
                                "%(subnet_id)s overlaps with cidr %(cidr)s "
                                "of subnet %(sub_id)s") % data)
                        self._raise_contrail_exception(
                            'BadRequest', resource='router', msg=msg)
        except vnc_exc.NoIdError:
            pass

    def _get_router_iface_vnc_info(self, context, router_obj, port_id=None,
                                   subnet_id=None):
        if port_id:
            vmi_obj, vn_obj, rtr_uuid, fixed_ips = self._get_vmi_info(port_id)
            net_id = vn_obj.uuid
            if rtr_uuid:
                self._raise_contrail_exception('PortInUse',
                                               net_id=net_id,
                                               port_id=port_id,
                                               device_id=rtr_uuid)
            if len(fixed_ips) != 1:
                self._raise_contrail_exception(
                    'BadRequest', resource='router',
                    msg='Router port must have exactly one fixed IP')

            subnet_id = fixed_ips[0]['subnet_id']

        subnet_vnc = self._subnet_handler._subnet_read(subnet_id=subnet_id)
        if not subnet_vnc.default_gateway:
            self._raise_contrail_exception(
                'BadRequest', resource='router',
                msg='Subnet for router interface must have a gateway IP')
        subnet_cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                 subnet_vnc.subnet.get_ip_prefix_len())

        self._check_for_dup_router_subnet(router_obj, subnet_id, subnet_cidr)

        if not port_id:
            vn_obj = self._subnet_handler.get_vn_obj_for_subnet_id(subnet_id)
            fixed_ip = {'ip_address': subnet_vnc.default_gateway,
                        'subnet_id': subnet_id}
            port_q = {
                'tenant_id': self._project_id_vnc_to_neutron(
                    vn_obj.parent_uuid),
                'network_id': vn_obj.uuid,
                'fixed_ips': [fixed_ip],
                'admin_state_up': True,
                'device_id': router_obj.uuid,
                'device_owner': n_constants.DEVICE_OWNER_ROUTER_INTF,
                'name': ''}
            port = self._vmi_handler.resource_create(context=context,
                                                     port_q=port_q)
            vmi_obj = self._vmi_handler.get_vmi_obj(port['id'])

        return vmi_obj, vn_obj, subnet_id

    def _get_vmi_info(self, port_id):
        vmi_obj = self._vmi_handler.get_vmi_obj(
            port_id, fields=['logical_router_back_refs',
                             'instance_ip_back_refs'])
        net_id = self._vmi_handler.get_vmi_net_id(vmi_obj)
        port_req_memo = {'virtual-machines': {},
                         'instance-ips': {},
                         'subnets': {}}
        router_refs = getattr(vmi_obj, 'logical_router_back_refs', None)
        if router_refs:
            rtr_uuid = router_refs[0]['uuid']
        else:
            vm_ref = vmi_obj.get_virtual_machine_refs()
            if vm_ref:
                rtr_uuid = self._vmi_handler.get_port_gw_id(vm_ref[0],
                                                            port_req_memo)
            else:
                rtr_uuid = None

        vn_obj = self._vnc_lib.virtual_network_read(id=net_id)
        fixed_ips = self._vmi_handler.get_vmi_ip_dict(vmi_obj, vn_obj,
                                                      port_req_memo)
        return vmi_obj, vn_obj, rtr_uuid, fixed_ips

    def add_router_interface(self, context, router_id, port_id=None,
                             subnet_id=None):
        router_obj = self._resource_get(id=router_id)

        if not port_id and not subnet_id:
            self._raise_contrail_exception(
                'BadRequest', resource='router',
                msg='Either port or subnet must be specified')

        vmi_obj, vn_obj, subnet_id = self._get_router_iface_vnc_info(
            context, router_obj, port_id=port_id, subnet_id=subnet_id)

        vmi_obj.set_virtual_machine_interface_device_owner(
            n_constants.DEVICE_OWNER_ROUTER_INTF)
        self._vnc_lib.virtual_machine_interface_update(vmi_obj)
        router_obj.add_virtual_machine_interface(vmi_obj)
        self._resource_update(router_obj)
        info = {
            'id': router_id,
            'tenant_id': self._project_id_vnc_to_neutron(vn_obj.parent_uuid),
            'port_id': vmi_obj.uuid,
            'subnet_id': subnet_id}
        return info

    def remove_router_interface(self, context, router_id, port_id=None,
                                subnet_id=None):
        router_obj = self._resource_get(id=router_id)
        tenant_id = None
        vmi_obj = None
        if port_id:
            vmi_obj, vn_obj, rtr_uuid, fixed_ips = self._get_vmi_info(port_id)
            if not rtr_uuid:
                self._raise_contrail_exception('RouterInterfaceNotFound',
                                               router_id=router_id,
                                               port_id=port_id)
            port_subnet_id = fixed_ips[0]['subnet_id']
            if subnet_id and (port_subnet_id != subnet_id):
                self._raise_contrail_exception('SubnetMismatchForPort',
                                               port_id=port_id,
                                               subnet_id=subnet_id)
            subnet_id = port_subnet_id
        elif subnet_id:
            vn_obj = self._subnet_handler.get_vn_obj_for_subnet_id(subnet_id)

            for intf in router_obj.get_virtual_machine_interface_refs() or []:
                port_id = intf['uuid']
                _, _, _, fixed_ips = self._get_vmi_info(port_id)
                if subnet_id == fixed_ips[0]['subnet_id']:
                    break
            else:
                msg = ("Subnet %s not connected to router %s "
                       % (router_id, subnet_id))
                self._raise_contrail_exception('BadRequest',
                                               resource='router', msg=msg)
        tenant_id = self._project_id_vnc_to_neutron(vn_obj.parent_uuid)
        if not vmi_obj:
            vmi_obj = self._vnc_lib.virtual_machine_interface_read(id=port_id)
        router_obj.del_virtual_machine_interface(vmi_obj)
        self._vnc_lib.logical_router_update(router_obj)
        self._vmi_handler.resource_delete(context, port_id=port_id)
        info = {'id': router_id,
                'tenant_id': tenant_id,
                'port_id': port_id,
                'subnet_id': subnet_id}
        return info


class LogicalRouterHandler(LogicalRouterGetHandler,
                           LogicalRouterCreateHandler,
                           LogicalRouterDeleteHandler,
                           LogicalRouterUpdateHandler):
    pass
