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

import uuid

from cfgm_common import exceptions as vnc_exc
import eventlet
import netaddr
from neutron.common import constants as n_constants
from neutron.common.config import cfg
from vnc_api import vnc_api

import contrail_res_handler as res_handler
import fip_res_handler
import sg_res_handler as sg_handler
import subnet_res_handler as subnet_handler
import vn_res_handler as vn_handler


class VMInterfaceMixin(object):
    @staticmethod
    def _port_fixed_ips_is_present(check, against):
        # filters = {'fixed_ips': {'ip_address': ['20.0.0.5', '20.0.0.6']}}
        # check = {'ip_address': ['20.0.0.5', '20.0.0.6']}
        # against = [{'subnet_id': 'uuid', 'ip_address': u'20.0.0.5'}]

        for item in against:
            result = True
            for k in item.keys():
                if k in check and item[k] not in check[k]:
                    result = False

            if result:
                return True

        return False

    @staticmethod
    def _get_vmi_memo_req_dict(vn_objs, iip_objs, vm_objs):
        memo_req = {'networks': {},
                    'subnets': {},
                    'virtual-machines': {},
                    'instance-ips': {}}

        for vn_obj in vn_objs or []:
            memo_req['networks'][vn_obj.uuid] = vn_obj
            memo_req['subnets'][vn_obj.uuid] = (
                subnet_handler.SubnetHandler.get_vn_subnets(vn_obj))

        for iip_obj in iip_objs or []:
            memo_req['instance-ips'][iip_obj.uuid] = iip_obj

        for vm_obj in vm_objs or []:
            memo_req['virtual-machines'][vm_obj.uuid] = vm_obj

        return memo_req

    @staticmethod
    def _get_extra_dhcp_opts(vmi_obj):
        dhcp_options_list = (
            vmi_obj.get_virtual_machine_interface_dhcp_option_list())
        if dhcp_options_list and dhcp_options_list.dhcp_option:
            dhcp_options = []
            for dhcp_option in dhcp_options_list.dhcp_option:
                pair = {'opt_value': dhcp_option.dhcp_option_value,
                        'opt_name': dhcp_option.dhcp_option_name}
                dhcp_options.append(pair)
            return dhcp_options

    @staticmethod
    def _get_allowed_adress_pairs(vmi_obj):
        allowed_address_pairs = (
            vmi_obj.get_virtual_machine_interface_allowed_address_pairs())
        if (allowed_address_pairs and
                allowed_address_pairs.allowed_address_pair):
            address_pairs = []
            for aap in allowed_address_pairs.allowed_address_pair:
                pair = {}
                pair['mac_address'] = aap.mac
                if aap.ip.get_ip_prefix_len() == 32:
                    pair['ip_address'] = '%s' % (aap.ip.get_ip_prefix())
                else:
                    pair['ip_address'] = '%s/%s' % (aap.ip.get_ip_prefix(),
                                                    aap.ip.get_ip_prefix_len())
                address_pairs.append(pair)
            return address_pairs

    @staticmethod
    def _ip_address_to_subnet_id(ip_addr, vn_obj, memo_req):
        subnets_info = memo_req['subnets'].get(vn_obj.uuid)
        for subnet_info in subnets_info or []:
            if (netaddr.IPAddress(ip_addr) in
                    netaddr.IPSet([subnet_info['cidr']])):
                return subnet_info['id']

        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                  subnet_vnc.subnet.get_ip_prefix_len())
                if netaddr.IPAddress(ip_addr) in netaddr.IPSet([cidr]):
                    return subnet_vnc.subnet_uuid

    def get_vmi_ip_dict(self, vmi_obj, vn_obj, port_req_memo):
        ip_dict_list = []
        ip_back_refs = getattr(vmi_obj, 'instance_ip_back_refs', None)
        for ip_back_ref in ip_back_refs or []:
            iip_uuid = ip_back_ref['uuid']
            # fetch it from request context cache/memo if there
            try:
                ip_obj = port_req_memo['instance-ips'][iip_uuid]
            except KeyError:
                try:
                    ip_obj = self._vnc_lib.instance_ip_read(id=iip_uuid)
                except vnc_exc.NoIdError:
                    continue

            ip_addr = ip_obj.get_instance_ip_address()
            subnet_id = self._ip_address_to_subnet_id(ip_addr, vn_obj,
                                                      port_req_memo)
            ip_q_dict = {'ip_address': ip_addr,
                         'subnet_id': subnet_id}

            ip_dict_list.append(ip_q_dict)

        return ip_dict_list

    def get_vmi_net_id(self, vmi_obj):
        net_refs = vmi_obj.get_virtual_network_refs()
        if net_refs:
            return net_refs[0]['uuid']

    def _extract_gw_id_from_vm_fq_name(self, vm_fq_name_str):
        """Extract the gateway id from vm fq name.

        Eg.
        vm fq name will be of the format :
        "default-domain__demo__si_2d192e48-db2b-4978-8ee3-0454a0fa691d__1..."

        Extract '2d192e48-db2b-4978-8ee3-0454a0fa691d' and return it
        """
        try:
            gw_id = vm_fq_name_str.split('si_')
            return gw_id[1].split('__')[0]
        except Exception:
            # any exception return None
            return None

    def get_port_gw_id(self, vm_ref, port_req_memo):
        # try to extract the gw id from the vm fq_name.
        # read the vm and si object only if necessary
        gw_id = self._extract_gw_id_from_vm_fq_name(vm_ref['to'][-1])
        if gw_id:
            return gw_id

        vm_uuid = vm_ref['uuid']
        vm_obj = None
        vm_obj = port_req_memo['virtual-machines'].get(vm_uuid)

        if vm_obj is None:
            try:
                vm_obj = self._vnc_lib.virtual_machine_read(id=vm_uuid)
            except vnc_exc.NoIdError:
                return None

            port_req_memo['virtual-machines'][vm_uuid] = vm_obj

        si_refs = vm_obj.get_service_instance_refs()
        if not si_refs:
            return None

        try:
            si_obj = self._vnc_lib.service_instance_read(
                id=si_refs[0]['uuid'],
                fields=["logical_router_back_refs"])
        except vnc_exc.NoIdError:
            return None

        rtr_back_refs = getattr(si_obj, "logical_router_back_refs", None)
        if rtr_back_refs:
            return rtr_back_refs[0]['uuid']

    def _get_vmi_device_id_owner(self, vmi_obj, port_req_memo):
        # port can be router interface or vm interface
        # for performance read logical_router_back_ref only when we have to
        device_id = ''
        device_owner = None

        router_refs = getattr(vmi_obj, 'logical_router_back_refs', None)
        if router_refs is not None:
            device_id = router_refs[0]['uuid']
        elif vmi_obj.parent_type == 'virtual-machine':
            device_id = vmi_obj.parent_name
        elif vmi_obj.get_virtual_machine_refs():
            vm_ref = vmi_obj.get_virtual_machine_refs()[0]
            if vm_ref['to'][-1] == vm_ref['uuid']:
                device_id = vm_ref['to'][-1]
            else:
                # this is a router gw port. Get the router id
                rtr_uuid = self.get_port_gw_id(vm_ref, port_req_memo)
                if rtr_uuid:
                    device_id = rtr_uuid
                    device_owner = n_constants.DEVICE_OWNER_ROUTER_GW

        return device_id, device_owner

    def _get_port_bindings(self, vmi_obj):
        vmi_bindings_kvps = None
        if hasattr(vmi_obj, 'get_virtual_machine_interface_bindings'):
            vmi_bindings_kvps = vmi_obj.get_virtual_machine_interface_bindings()

        if vmi_bindings_kvps:
            vmi_bindings = vmi_bindings_kvps.exportDict(name_=None) or {}
        else:
            vmi_bindings = {}

        ret_bindings = {}
        for k,v in vmi_bindings.items():
            ret_bindings['binding:%s'%(k)] = v

        # 1. upgrade case, port created before bindings prop was
        #    defined on vmi OR
        # 2. defaults for keys needed by neutron
        try:
            ret_bindings['binding:vif_details'] = vmi_bindings['vif_details']
        except KeyError:
            ret_bindings['binding:vif_details'] = {'port_filter': True}
        try:
            ret_bindings['binding:vif_type'] = vmi_bindings['vif_type']
        except KeyError:
            ret_bindings['binding:vif_type'] = 'vrouter'
        try:
            ret_bindings['binding:vnic_type'] = vmi_bindings['vnic_type']
        except KeyError:
            ret_bindings['binding:vnic_type'] = 'normal'

        return ret_bindings

    def _vmi_to_neutron_port(self, vmi_obj, port_req_memo=None,
                             extensions_enabled=False, fields=None):
        port_q_dict = {}

        if not getattr(vmi_obj, 'display_name'):
            # for ports created directly via vnc_api
            port_q_dict['name'] = vmi_obj.get_fq_name()[-1]
        else:
            port_q_dict['name'] = vmi_obj.display_name

        port_q_dict['id'] = vmi_obj.uuid

        net_id = self.get_vmi_net_id(vmi_obj)
        if not net_id:
            # TODO() hack to force network_id on default port
            # as neutron needs it
            net_id = self._vnc_lib.obj_to_id(vnc_api.VirtualNetwork())

        if port_req_memo is None:
            # create a memo only for this port's conversion in this method
            port_req_memo = {}

        if 'networks' not in port_req_memo:
            port_req_memo['networks'] = {}
        if 'subnets' not in port_req_memo:
            port_req_memo['subnets'] = {}
        if 'virtual-machines' not in port_req_memo:
            port_req_memo['virtual-machines'] = {}

        try:
            vn_obj = port_req_memo['networks'][net_id]
        except KeyError:
            vn_obj = self._vnc_lib.virtual_network_read(id=net_id)
            port_req_memo['networks'][net_id] = vn_obj
            subnets_info = (
                subnet_handler.SubnetHandler.get_vn_subnets(vn_obj))
            port_req_memo['subnets'][net_id] = subnets_info

        if vmi_obj.parent_type != "project":
            proj_id = self._project_id_vnc_to_neutron(vn_obj.parent_uuid)
        else:
            proj_id = self._project_id_vnc_to_neutron(vmi_obj.parent_uuid)

        port_q_dict['tenant_id'] = proj_id
        port_q_dict['network_id'] = net_id

        # TODO() RHS below may need fixing
        port_q_dict['mac_address'] = ''
        mac_refs = vmi_obj.get_virtual_machine_interface_mac_addresses()
        if mac_refs:
            port_q_dict['mac_address'] = mac_refs.mac_address[0]

        extra_dhcp_opts = self._get_extra_dhcp_opts(vmi_obj)
        if extra_dhcp_opts:
            port_q_dict['extra_dhcp_opts'] = extra_dhcp_opts

        address_pairs = self._get_allowed_adress_pairs(vmi_obj)
        if address_pairs:
            port_q_dict['allowed_address_pairs'] = address_pairs

        port_q_dict['fixed_ips'] = self.get_vmi_ip_dict(vmi_obj, vn_obj,
                                                        port_req_memo)

        port_q_dict['security_groups'] = []
        sg_refs = vmi_obj.get_security_group_refs()
        # read the no rule sg
        no_rule_sg = res_handler.SGHandler(
            self._vnc_lib).get_no_rule_security_group()
        for sg_ref in sg_refs or []:
            if no_rule_sg and sg_ref['uuid'] == no_rule_sg.uuid:
                # hide the internal sg
                continue

            port_q_dict['security_groups'].append(sg_ref['uuid'])

        port_q_dict['admin_state_up'] = vmi_obj.get_id_perms().enable

        device_id, device_owner = self._get_vmi_device_id_owner(vmi_obj,
                                                                port_req_memo)
        port_q_dict['device_id'] = device_id

        if device_owner is not None:
            port_q_dict['device_owner'] = device_owner
        else:
            port_q_dict['device_owner'] = (
                vmi_obj.get_virtual_machine_interface_device_owner() or '')

        if port_q_dict['device_id']:
            port_q_dict['status'] = n_constants.PORT_STATUS_ACTIVE
        else:
            port_q_dict['status'] = n_constants.PORT_STATUS_DOWN

        if extensions_enabled:
            extra_dict = {'contrail:fq_name': vmi_obj.get_fq_name()}
            port_q_dict.update(extra_dict)

        bindings_dict = self._get_port_bindings(vmi_obj)
        for k,v in bindings_dict.items():
            port_q_dict[k] = v

        if fields:
            port_q_dict = self._filter_res_dict(port_q_dict, fields)
        return port_q_dict

    def _set_vm_instance_for_vmi(self, vmi_obj, instance_name):
        """Set vm instance for the vmi.

        This function also deletes the old virtual_machine object
        associated with the vmi (if any) after the new virtual_machine
        object is associated with it.
        """
        vm_refs = vmi_obj.get_virtual_machine_refs()
        delete_vm_list = []
        for vm_ref in vm_refs or []:
            if vm_ref['to'] != [instance_name]:
                delete_vm_list.append(vm_ref)

        if instance_name or delete_vm_list:
            vm_handler = res_handler.VMachineHandler(self._vnc_lib)

        if instance_name:
            try:
                instance_obj = vm_handler.ensure_vm_instance(instance_name)
                vmi_obj.set_virtual_machine(instance_obj)
            except vnc_exc.RefsExistError as e:
                self._raise_contrail_exception(
                    'BadRequest', resource='port', msg=str(e))
            except vnc_exc.NoIdError:
                self._raise_contrail_exception(
                    'DeviceIDNotOwnedByTenant', resource='port',
                    device_id=instance_name)
        else:
            vmi_obj.set_virtual_machine_list([])

        if delete_vm_list:
            self._vnc_lib.virtual_machine_interface_update(vmi_obj)
            for vm_ref in delete_vm_list:
                try:
                    vm_handler._resource_delete(id=vm_ref['uuid'])
                except vnc_exc.RefsExistError:
                    pass

    def _set_vmi_security_groups(self, vmi_obj, sec_group_list,
                                 create_no_rule=False):
        vmi_obj.set_security_group_list([])
        for sg_id in sec_group_list or []:
            # TODO() optimize to not read sg (only uuid/fqn needed)
            sg_obj = self._vnc_lib.security_group_read(id=sg_id)
            vmi_obj.add_security_group(sg_obj)

        # When there is no-security-group for a port,the internal
        # no_rule group should be used.
        if create_no_rule and not sec_group_list:
            sg_obj = res_handler.SGHandler(
                self._vnc_lib).get_no_rule_security_group()
            vmi_obj.add_security_group(sg_obj)

    def _set_vmi_extra_dhcp_options(self, vmi_obj, extra_dhcp_options):
        dhcp_options = []
        for option_pair in extra_dhcp_options or []:
            option = vnc_api.DhcpOptionType(
                dhcp_option_name=option_pair['opt_name'],
                dhcp_option_value=option_pair['opt_value'])
            dhcp_options.append(option)

        if dhcp_options:
            olist = vnc_api.DhcpOptionsListType(dhcp_options)
            vmi_obj.set_virtual_machine_interface_dhcp_option_list(olist)
        else:
            vmi_obj.set_virtual_machine_interface_dhcp_option_list(None)

    def _set_vmi_allowed_addr_pairs(self, vmi_obj, allowed_addr_pairs):
        aap_array = []
        for address_pair in allowed_addr_pairs or []:
            mode = u'active-standby'
            if 'mac_address' not in address_pair:
                address_pair['mac_address'] = ""

            cidr = address_pair['ip_address'].split('/')
            if len(cidr) == 1:
                subnet = vnc_api.SubnetType(cidr[0], 32)
            elif len(cidr) == 2:
                subnet = vnc_api.SubnetType(cidr[0], int(cidr[1]))
            else:
                self._raise_contrail_exception(
                    'BadRequest', resource='port',
                    msg='Invalid address pair argument')

            aap_array.append(vnc_api.AllowedAddressPair(
                subnet,
                address_pair['mac_address'], mode))

        aaps = vnc_api.AllowedAddressPairs()
        if aap_array:
            aaps.set_allowed_address_pair(aap_array)
        vmi_obj.set_virtual_machine_interface_allowed_address_pairs(aaps)

    def _get_vmi_ip_list(self, vmi_obj):
        ip_back_refs = getattr(vmi_obj, 'instance_ip_back_refs', None)
        vmi_obj_ips = []
        if ip_back_refs:
            ip_handler = res_handler.InstanceIpHandler(self._vnc_lib)
            for ip_back_ref in ip_back_refs:
                try:
                    ip_obj = ip_handler.get_iip_obj(id=ip_back_ref['uuid'])
                except vnc_exc.NoIdError:
                    continue
            vmi_obj_ips.append(ip_obj.get_instance_ip_address())
        return vmi_obj_ips

    def _check_vmi_fixed_ips(self, vmi_obj, fixed_ips, net_id):
        vmi_obj_ips = self._get_vmi_ip_list(vmi_obj)
        ip_handler = res_handler.InstanceIpHandler(self._vnc_lib)
        for fixed_ip in fixed_ips or []:
            ip_addr = fixed_ip.get('ip_address')
            if not ip_addr or ip_addr in vmi_obj_ips:
                continue

            if ip_handler.is_ip_addr_in_net_id(ip_addr, net_id):
                self._raise_contrail_exception(
                    'IpAddressInUse', net_id=net_id,
                    ip_address=ip_addr, resource='port')

    def _neutron_port_to_vmi(self, port_q, vmi_obj=None, update=False):
        if 'name' in port_q and port_q['name']:
            vmi_obj.display_name = port_q['name']

        device_owner = port_q.get('device_owner')

        if (device_owner not in [n_constants.DEVICE_OWNER_ROUTER_INTF,
                                 n_constants.DEVICE_OWNER_ROUTER_GW]
                and 'device_id' in port_q):
            self._set_vm_instance_for_vmi(vmi_obj, port_q.get('device_id'))

        if device_owner is not None:
            vmi_obj.set_virtual_machine_interface_device_owner(device_owner)

        if ('mac_address' in port_q and port_q['mac_address']):
            mac_addrs_obj = vnc_api.MacAddressesType()
            mac_addrs_obj.set_mac_address([port_q['mac_address']])
            vmi_obj.set_virtual_machine_interface_mac_addresses(mac_addrs_obj)

        if 'security_groups' in port_q:
            self._set_vmi_security_groups(vmi_obj,
                                          port_q.get('security_groups'),
                                          update)

        if 'admin_state_up' in port_q:
            id_perms = vmi_obj.get_id_perms()
            id_perms.enable = port_q['admin_state_up']
            vmi_obj.set_id_perms(id_perms)

        if 'extra_dhcp_opts' in port_q:
            self._set_vmi_extra_dhcp_options(vmi_obj,
                                             port_q.get('extra_dhcp_opts'))

        if ('allowed_address_pairs' in port_q):
            self._set_vmi_allowed_addr_pairs(
                vmi_obj, port_q.get('allowed_address_pairs'))

        if 'fixed_ips' in port_q:
            net_id = (port_q.get('network_id') or
                      vmi_obj.get_virtual_network_refs()[0]['uuid'])
            self._check_vmi_fixed_ips(vmi_obj, port_q.get('fixed_ips'), net_id)

        if hasattr(vmi_obj, 'add_virtual_machine_interface_bindings'):
            # pick binding keys from neutron repr and persist as kvp elements.
            # it is assumed allowing/denying oper*key is done at neutron-server.
            vmi_binding_kvps = dict((k.replace('binding:',''), v)
                for k,v in port_q.items() if k.startswith('binding:'))
            for k,v in vmi_binding_kvps.items():
                vmi_obj.add_virtual_machine_interface_bindings(
                    vnc_api.KeyValuePair(key=k, value=v), elem_position=k)

        return vmi_obj

    def _create_instance_ips(self, vn_obj, vmi_obj, fixed_ips, ip_family="v4"):
        if fixed_ips is None:
            return

        # 1. find existing ips on port
        # 2. add new ips on port from update body
        # 3. delete old/stale ips on port
        subnets = dict()
        ipam_refs = vn_obj.get_network_ipam_refs()
        for ipam_ref in ipam_refs or []:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                  subnet_vnc.subnet.get_ip_prefix_len())
                subnets[subnet_vnc.subnet_uuid] = cidr

        stale_ip_ids = {}
        ip_handler = res_handler.InstanceIpHandler(self._vnc_lib)
        for iip in getattr(vmi_obj, 'instance_ip_back_refs', []):
            iip_obj = ip_handler.get_iip_obj(id=iip['uuid'])
            ip_addr = iip_obj.get_instance_ip_address()
            stale_ip_ids[ip_addr] = iip['uuid']

        created_iip_ids = []
        for fixed_ip in fixed_ips:
            try:
                ip_addr = fixed_ip.get('ip_address')
                if ip_addr is not None:
                    try:
                        # this ip survives to next gen
                        del stale_ip_ids[ip_addr]
                        continue
                    except KeyError:
                        pass

                    if netaddr.IPAddress(ip_addr).version == 4:
                        ip_family = "v4"
                    elif netaddr.IPAddress(ip_addr).version == 6:
                        ip_family = "v6"
                subnet_id = fixed_ip.get('subnet_id')
                if subnet_id and subnet_id not in subnets:
                    for iip_id in created_iip_ids:
                        ip_handler._resource_delete(id=iip_id)
                    self._raise_contrail_exception(
                        'BadRequest',
                        msg='Subnet invalid for network', resource='port')

                ip_family = fixed_ip.get('ip_family', ip_family)
                ip_id = ip_handler.create_instance_ip(vn_obj, vmi_obj, ip_addr,
                                                      subnet_id, ip_family)
                created_iip_ids.append(ip_id)
            except vnc_exc.HttpError as e:
                # Resources are not available
                for iip_id in created_iip_ids:
                    ip_handler._resource_delete(id=iip_id)
                if e.status_code == 400:
                    if 'subnet_id' in fixed_ip:
                        self._raise_contrail_exception(
                            'InvalidIpForSubnet',
                            ip_address=fixed_ip.get('ip_address'),
                            resource='port')
                    else:
                        self._raise_contrail_exception(
                            'InvalidIpForNetwork',
                            ip_address=fixed_ip.get('ip_address'),
                            resource='port')
                else:
                    self._raise_contrail_exception(
                        'IpAddressGenerationFailure',
                        net_id=vn_obj.get_uuid(), resource='port')
            except vnc_exc.PermissionDenied:
                   self._raise_contrail_exception(
                           'IpAddressInUse', net_id=vn_obj.get_uuid(),
                           ip_address=fixed_ip.get('ip_address'), resource='port')


        iips_total = list(created_iip_ids)
        for stale_ip, stale_id in stale_ip_ids.items():
            ip_handler.delete_iip_obj(stale_id)

        if hasattr(cfg.CONF, 'max_fixed_ips_per_port'):
            if len(iips_total) > cfg.CONF.max_fixed_ips_per_port:
                for iip_id in iips_total:
                    ip_handler.delete_iip_obj(iip_id)
                self._raise_contrail_exception(
                    'BadRequest',
                    msg="IIPS exceeds max limit")

    def get_vmi_tenant_id(self, vmi_obj):
        if vmi_obj.parent_type != "project":
            net_id = vmi_obj.get_virtual_network_refs()[0]['uuid']
            vn_get_handler = vn_handler.VNetworkGetHandler(self._vnc_lib)
            vn_obj = vn_get_handler.get_vn_obj(id=net_id)
            return vn_get_handler.get_vn_tenant_id(vn_obj)

        return self._project_id_vnc_to_neutron(vmi_obj.parent_uuid)

    def _validate_mac_address(self, project_id, net_id, mac_address):
        ports = self._vnc_lib.virtual_machine_interfaces_list(
            parent_id=project_id, back_ref_id=net_id, detail=True)

        for port in ports:
            macs = port.get_virtual_machine_interface_mac_addresses()
            for mac in macs.get_mac_address():
                if mac == mac_address:
                    raise self._raise_contrail_exception(
                        "MacAddressInUse", net_id=net_id, mac=mac_address,
                        resource='port')


class VMInterfaceCreateHandler(res_handler.ResourceCreateHandler,
                               VMInterfaceMixin):
    resource_create_method = 'virtual_machine_interface_create'

    def _get_tenant_id_for_create(self, context, resource):
        if context['is_admin'] and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context['tenant']):
            reason = ('Cannot create resource for another tenant')
            self._raise_contrail_exception('AdminRequired', reason=reason,
                                           resource='port')
        else:
            tenant_id = context['tenant']
        return tenant_id

    def _create_vmi_obj(self, port_q, vn_obj):
        project_id = self._project_id_neutron_to_vnc(port_q['tenant_id'])
        try:
            proj_obj = self._project_read(proj_id=project_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'ProjectNotFound',
                projec_id=project_id, resource='port')
        id_perms = vnc_api.IdPermsType(enable=True)
        vmi_uuid = str(uuid.uuid4())
        if port_q.get('name'):
            vmi_name = port_q['name']
        else:
            vmi_name = vmi_uuid
        vmi_obj = vnc_api.VirtualMachineInterface(vmi_name, proj_obj,
                                                  id_perms=id_perms)
        vmi_obj.uuid = vmi_uuid
        vmi_obj.set_virtual_network(vn_obj)
        vmi_obj.set_security_group_list([])
        if ('security_groups' not in port_q or
                port_q['security_groups'].__class__ is object):
            sg_obj = vnc_api.SecurityGroup("default", proj_obj)
            uid = sg_handler.SecurityGroupHandler(
                self._vnc_lib)._ensure_default_security_group_exists(
                proj_obj.uuid)
            sg_obj.uuid = uid
            vmi_obj.add_security_group(sg_obj)

        return vmi_obj

    def resource_create(self, context, port_q):
        if 'network_id' not in port_q or 'tenant_id' not in port_q:
            raise self._raise_contrail_exception(
                'BadRequest', resource='port',
                msg="'tenant_id' and 'network_id' are mandatory")

        apply_subnet_host_routes = self._kwargs.get(
            'apply_subnet_host_routes', False)

        net_id = port_q['network_id']
        try:
            vn_obj = self._vnc_lib.virtual_network_read(id=net_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'NetworkNotFound', net_id=net_id, resource='port')

        tenant_id = self._get_tenant_id_for_create(context, port_q)
        proj_id = self._project_id_neutron_to_vnc(tenant_id)

        # if mac-address is specified, check against the exisitng ports
        # to see if there exists a port with the same mac-address
        if 'mac_address' in port_q:
            self._validate_mac_address(proj_id, net_id, port_q['mac_address'])

        # initialize port object
        vmi_obj = self._create_vmi_obj(port_q, vn_obj)
        vmi_obj = self._neutron_port_to_vmi(port_q, vmi_obj=vmi_obj)

        # determine creation of v4 and v6 ip object
        ip_obj_v4_create = False
        ip_obj_v6_create = False
        fixed_ips = []
        ipam_refs = vn_obj.get_network_ipam_refs() or []
        for ipam_ref in ipam_refs:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                  subnet_vnc.subnet.get_ip_prefix_len())
                if not ip_obj_v4_create and (
                        netaddr.IPNetwork(cidr).version == 4):
                    ip_obj_v4_create = True
                    fixed_ips.append(
                        {'subnet_id': subnet_vnc.subnet_uuid,
                         'ip_family': 'v4'})
                if not ip_obj_v6_create and (
                        netaddr.IPNetwork(cidr).version == 6):
                    ip_obj_v6_create = True
                    fixed_ips.append(
                        {'subnet_id': subnet_vnc.subnet_uuid,
                         'ip_family': 'v6'})

        # create the object
        port_id = self._resource_create(vmi_obj)
        try:
            if 'fixed_ips' in port_q:
                self._create_instance_ips(vn_obj, vmi_obj, port_q['fixed_ips'])
            elif vn_obj.get_network_ipam_refs():
                self._create_instance_ips(vn_obj, vmi_obj, fixed_ips)
        except Exception as e:
            # failure in creating the instance ip. Roll back
            self._resource_delete(id=port_id)
            raise e

        # TODO() below reads back default parent name, fix it
        vmi_obj = self._resource_get(id=port_id,
                                     fields=['instance_ip_back_refs'])
        ret_port_q = self._vmi_to_neutron_port(vmi_obj)

        # create interface route table for the port if
        # subnet has a host route for this port ip.
        if apply_subnet_host_routes:
            subnet_host_handler = subnet_handler.SubnetHostRoutesHandler(
                self._vnc_lib)
            subnet_host_handler.port_check_and_add_iface_route_table(
                ret_port_q['fixed_ips'], vn_obj, vmi_obj)

        return ret_port_q


class VMInterfaceUpdateHandler(res_handler.ResourceUpdateHandler,
                               VMInterfaceMixin):
    resource_update_method = 'virtual_machine_interface_update'

    def resource_update(self, context, port_id, port_q):
        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        port_q['id'] = port_id
        try:
            vmi_obj = self._resource_get(id=port_q.get('id'),
                                         fields=['instance_ip_back_refs'])
        except vnc_exc.NoIdError:
            raise self._raise_contrail_exception(
                'PortNotFound', port_id=port_q.get('id'),
                resource='port')

        net_id = vmi_obj.get_virtual_network_refs()[0]['uuid']
        vn_obj = self._vnc_lib.virtual_network_read(id=net_id)
        if port_q.get('mac_address'):
            self._validate_mac_address(
                vmi_obj.parent_uuid,
                net_id, port_q['mac_address'])

        vmi_obj = self._neutron_port_to_vmi(port_q, vmi_obj=vmi_obj,
                                            update=True)
        if 'fixed_ips' in port_q:
            self._create_instance_ips(vn_obj, vmi_obj, port_q['fixed_ips'])

        self._resource_update(vmi_obj)
        vmi_obj = self._resource_get(id=port_id,
                                     fields=['instance_ip_back_refs'])
        ret_port_q = self._vmi_to_neutron_port(
            vmi_obj, extensions_enabled=contrail_extensions_enabled)

        return ret_port_q


class VMInterfaceDeleteHandler(res_handler.ResourceDeleteHandler,
                               VMInterfaceMixin):
    resource_delete_method = 'virtual_machine_interface_delete'

    def resource_delete(self, context, port_id):
        try:
            vmi_obj = self._resource_get(back_refs=True, id=port_id)
        except vnc_exc.NoIdError:
            raise self._raise_contrail_exception(
                "PortNotFound", port_id=port_id, resource='port')
        if vmi_obj.parent_type == 'virtual-machine':
            instance_id = vmi_obj.parent_uuid
        else:
            vm_refs = vmi_obj.get_virtual_machine_refs()
            if vm_refs:
                instance_id = vm_refs[0]['uuid']
            else:
                instance_id = None
        if vmi_obj.get_logical_router_back_refs():
            self._raise_contrail_exception(
                'PortInUse', port_id=port_id,
                net_id=self.get_vmi_net_id(vmi_obj),
                device_id=instance_id,
                resource='port')

        # release instance IP address
        iip_back_refs = list((getattr(vmi_obj, 'instance_ip_back_refs', [])))
        ip_handler = res_handler.InstanceIpHandler(self._vnc_lib)

        for iip_back_ref in iip_back_refs or []:
            # if name contains IP address then this is shared ip
            iip_obj = ip_handler.get_iip_obj(id=iip_back_ref['uuid'])

            # in case of shared ip only delete the link to the VMI
            iip_obj.del_virtual_machine_interface(vmi_obj)
            if not iip_obj.get_virtual_machine_interface_refs():
                ip_handler._resource_delete(id=iip_back_ref['uuid'])
            else:
                ip_handler._resource_update(iip_obj)
        # disassociate any floating IP used by instance
        fip_back_refs = getattr(vmi_obj, 'floating_ip_back_refs', None)
        if fip_back_refs:
            fip_handler = fip_res_handler.FloatingIpHandler(self._vnc_lib)
            for fip_back_ref in fip_back_refs:
                fip_handler.resource_update(context, fip_back_ref['uuid'],
                                            {'port_id': None})

        self._resource_delete(id=port_id)

        # delete any interface route table associatd with the port
        for rt_ref in vmi_obj.get_interface_route_table_refs() or []:
            try:
                self._vnc_lib.interface_route_table_delete(id=rt_ref['uuid'])
            except vnc_exc.NoIdError:
                pass

        # delete instance if this was the last port
        try:
            if instance_id:
                self._vnc_lib.virtual_machine_delete(id=instance_id)
        except vnc_exc.RefsExistError:
            pass


class VMInterfaceGetHandler(res_handler.ResourceGetHandler, VMInterfaceMixin):
    resource_list_method = 'virtual_machine_interfaces_list'
    resource_get_method = 'virtual_machine_interface_read'
    back_ref_fields = ['logical_router_back_refs', 'instance_ip_back_refs',
                       'floating_ip_back_refs']

    # returns vm objects, net objects, and instance ip objects
    def _get_vmis_nets_ips(self, context, project_ids=None,
                           device_ids=None, vmi_uuids=None, vn_ids=None):
        vn_list_handler = vn_handler.VNetworkGetHandler(self._vnc_lib)
        pool = eventlet.GreenPool()
        vn_objs_t = pool.spawn(vn_list_handler.get_vn_obj_list,
                               parent_id=project_ids, detail=True)

        vmi_objs_t = None
        vmi_obj_uuids_t = None
        back_ref_id = []
        if device_ids:
            back_ref_id = device_ids

        if vn_ids:
            back_ref_id.extend(vn_ids)

        if back_ref_id:
            vmi_objs_t = pool.spawn(self._resource_list,
                                    back_ref_id=back_ref_id, back_refs=True)

        if vmi_uuids:
            vmi_obj_uuids_t = pool.spawn(self._resource_list,
                                         obj_uuids=vmi_uuids, back_refs=True)
        elif not back_ref_id:
            vmi_objs_t = pool.spawn(self._resource_list,
                                    parent_id=project_ids, back_refs=True)

        # if admin no need to filter we can retrieve all the ips object
        # with only one call
        if context['is_admin']:
            iip_list_handler = res_handler.InstanceIpHandler(self._vnc_lib)
            iip_objs_t = pool.spawn(iip_list_handler.get_iip_obj_list,
                                    detail=True)

        pool.waitall()

        vn_objs = vn_objs_t._exit_event._result
        if context['is_admin']:
            iips_objs = iip_objs_t._exit_event._result
        else:
            vn_ids = [vn_obj.uuid for vn_obj in vn_objs]
            iip_list_handler = res_handler.InstanceIpHandler(self._vnc_lib)
            iips_objs = iip_list_handler.get_iip_obj_list(back_ref_id=vn_ids,
                                                          detail=True)

        vmi_objs = []
        if vmi_objs_t is not None:
            vmi_objs = vmi_objs_t._exit_event._result

        if vmi_obj_uuids_t is not None:
            vmi_objs.extend(vmi_obj_uuids_t._exit_event._result)

        return vmi_objs, vn_objs, iips_objs

    # get vmi related resources filtered by project_ids
    def _get_vmi_resources(self, context, project_ids=None, ids=None,
                           device_ids=None, vn_ids=None):
        if device_ids:
            rtr_objs = self._vnc_lib.logical_routers_list(obj_uuids=device_ids,
                                                          detail=True)
            if not ids:
                ids = []
            for rtr_obj in rtr_objs or []:
                intfs = rtr_obj.get_virtual_machine_interface_refs()
                for intf in intfs or []:
                    ids.append(intf['uuid'])

        return self._get_vmis_nets_ips(context, project_ids=project_ids,
                                       device_ids=device_ids,
                                       vmi_uuids=ids, vn_ids=vn_ids)

    def _get_ports_dict(self, vmi_objs, memo_req, extensions_enabled=False):
        ret_ports = []
        for vmi_obj in vmi_objs or []:
            try:
                port_info = self._vmi_to_neutron_port(
                    vmi_obj, memo_req, extensions_enabled=extensions_enabled)
            except vnc_exc.NoIdError:
                continue
            ret_ports.append(port_info)

        return ret_ports

    def get_vmi_list(self, **kwargs):
        return self._resource_list(**kwargs)

    def resource_list(self, context=None, filters=None, fields=None):
        if not context:
            context = {'is_admin': True}

        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)

        if filters is None:
            filters = {}

        project_ids = []
        tenant_ids = []
        if not context['is_admin']:
            tenant_ids = [context['tenant']]
            project_ids = [self._project_id_neutron_to_vnc(context['tenant'])]
        elif 'tenant_id' in filters:
            tenant_ids = filters['tenant_id']
            project_ids = self._validate_project_ids(context,
                                                     filters['tenant_id'])

        # choose the most appropriate way of retrieving ports
        # before pruning by other filters
        if 'device_id' in filters:
            vmi_objs, vn_objs, iip_objs = self._get_vmi_resources(
                context, project_ids, device_ids=filters['device_id'],
                vn_ids=filters.get('network_id'))
        else:
            vmi_objs, vn_objs, iip_objs = self._get_vmi_resources(
                context, project_ids, ids=filters.get('id'),
                vn_ids=filters.get('network_id'))

        memo_req = self._get_vmi_memo_req_dict(vn_objs, iip_objs, None)
        ports = self._get_ports_dict(
            vmi_objs, memo_req,
            extensions_enabled=contrail_extensions_enabled)

        # prune phase
        ret_ports = []
        for port in ports:
            if tenant_ids and port['tenant_id'] not in tenant_ids:
                continue

            # TODO(safchain) revisit these filters if necessary
            if not self._filters_is_present(filters, 'name', port['name']):
                continue
            if not self._filters_is_present(
                    filters, 'device_owner', port['device_owner']):
                continue
            if 'fixed_ips' in filters and not self._port_fixed_ips_is_present(
                    filters['fixed_ips'], port['fixed_ips']):
                continue

            if fields:
                port = self._filter_res_dict(port, fields)
            ret_ports.append(port)

        return ret_ports

    def get_vmi_obj(self, vmi_id, fields=None):
        return self._resource_get(id=vmi_id, fields=fields)

    def resource_get(self, context, port_id, fields=None):
        contrail_extensions_enabled = self._kwargs.get(
            'contrail_extensions_enabled', False)
        try:
            vmi_obj = self._resource_get(id=port_id,
                                         fields=['instance_ip_back_refs'])
        except vnc_exc.NoIdError:
            self._raise_contrail_exception('PortNotFound', port_id=port_id,
                                           resource='port')

        ret_port_q = self._vmi_to_neutron_port(
            vmi_obj, extensions_enabled=contrail_extensions_enabled,
            fields=fields)

        return ret_port_q

    def resource_count(self, context, filters=None):
        count = self._resource_count_optimized(filters)
        if count is not None:
            return count

        if (filters.get('device_owner') == 'network:dhcp' or
                'network:dhcp' in filters.get('device_owner', [])):
            return 0

        if 'tenant_id' in filters:
            if isinstance(filters['tenant_id'], list):
                project_id = self._project_id_neutron_to_vnc(
                    filters['tenant_id'][0])
            else:
                project_id = self._project_id_neutron_to_vnc(
                    filters['tenant_id'])

            nports = len(self._resource_list(parent_id=project_id))
        else:
            # across all projects - TODO() very expensive,
            # get only a count from api-server!
            nports = len(self.resource_list(filters=filters))

        return nports


class VMInterfaceHandler(VMInterfaceGetHandler,
                         VMInterfaceCreateHandler,
                         VMInterfaceDeleteHandler,
                         VMInterfaceUpdateHandler):
    pass
