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
from neutron_plugin_contrail.plugins.opencontrail import contrail_plugin_base
from vnc_api import common as vnc_api_common
from vnc_api import vnc_api


class ContrailResourceHandler(object):

    def __init__(self, vnc_lib, **kwargs):
        self._vnc_lib = vnc_lib
        self._kwargs = kwargs

    @staticmethod
    def _filters_is_present(filters, key_name, match_value):
        if not filters:
            return True

        if key_name in filters:
            try:
                if key_name == 'tenant_id':
                    filter_value = [t_id for t_id in filters[key_name]]
                else:
                    filter_value = filters[key_name]
                filter_value.index(match_value)
            except ValueError:  # not in requested list
                return False
        return True

    @staticmethod
    def _raise_contrail_exception(exc, **kwargs):
        exc_info = {'exception': exc}
        exc_info.update(kwargs)
        contrail_plugin_base._raise_contrail_error(exc_info,
                                                   kwargs.get('resource'))

    @staticmethod
    def _validate_project_ids(context, project_ids=None):
        if context and not context['is_admin']:
            return [context['tenant']]

        ids = []
        for project_id in project_ids:
            try:
                ids.append(
                    ContrailResourceHandler._project_id_neutron_to_vnc(
                        project_id))
            except ValueError:
                pass
        return ids

    @staticmethod
    def _project_id_vnc_to_neutron(proj_id):
        return proj_id.replace("-", "")

    @staticmethod
    def _project_id_neutron_to_vnc(proj_id):
        return str(uuid.UUID(proj_id))

    @staticmethod
    def _filter_res_dict(res_dict, fields):
        new_res_dict = {}
        for f in fields:
            new_res_dict[f] = res_dict.get(f)
        return new_res_dict

    def _project_read(self, proj_id=None, fq_name=None):
        if proj_id:
            proj_id = self._project_id_neutron_to_vnc(proj_id)
        return self._vnc_lib.project_read(id=proj_id, fq_name=fq_name)

    def _project_list_domain(self, domain_id):
        # TODO() till domain concept is not present in keystone
        fq_name = ['default-domain']
        resp_dict = self._vnc_lib.projects_list(parent_fq_name=fq_name)

        return resp_dict['projects']


class ResourceCreateHandler(ContrailResourceHandler):
    resource_create_method = None

    def _resource_create(self, obj):
        create_method = getattr(self._vnc_lib, self.resource_create_method)
        try:
            obj_uuid = create_method(obj)
        except (vnc_exc.PermissionDenied, vnc_exc.BadRequest) as e:
            self._raise_contrail_exception(
                'BadRequest', msg=str(e))
        return obj_uuid


class ResourceDeleteHandler(ContrailResourceHandler):
    resource_delete_method = None

    def _resource_delete(self, id=None, fq_name=None):
        delete_method = getattr(self._vnc_lib, self.resource_delete_method)
        delete_method(id=id, fq_name=fq_name)


class ResourceUpdateHandler(ContrailResourceHandler):
    resource_update_method = None

    def _resource_update(self, obj):
        getattr(self._vnc_lib, self.resource_update_method)(obj)


class ResourceGetHandler(ContrailResourceHandler):
    back_ref_fields = None
    resource_list_method = None
    resource_get_method = None
    detail = True

    def _resource_list(self, back_refs=False, **kwargs):
        if back_refs:
            kwargs['fields'] = list(set((kwargs.get('fields', [])) +
                                        (self.back_ref_fields or [])))
        if 'detail' not in kwargs:
            kwargs['detail'] = self.detail

        return getattr(self._vnc_lib, self.resource_list_method)(**kwargs)

    def _resource_get(self, resource_get_method=None, back_refs=False,
                      **kwargs):
        if back_refs:
            kwargs['fields'] = list(set((kwargs.get('fields', [])) +
                                    (self.back_ref_fields or [])))
        if resource_get_method:
            return getattr(self._vnc_lib, resource_get_method)(**kwargs)

        return getattr(self._vnc_lib, self.resource_get_method)(**kwargs)

    def _resource_count_optimized(self, filters):
        if filters and ('tenant_id' not in filters or len(filters.keys()) > 1):
            return None

        project_ids = filters.get('tenant_id') if filters else None
        if not isinstance(project_ids, list):
            project_ids = [project_ids]

        json_resource = self.resource_list_method.replace("_", "-")
        json_resource = json_resource.replace('-list', '')
        if self.resource_list_method == "floating_ips_list":
            count = lambda pid: self._resource_list(
                back_ref_id=pid, count=True, back_refs=False,
                detail=False)[json_resource]['count']
        else:
            count = lambda pid: self._resource_list(
                parent_id=pid, count=True, back_refs=False,
                detail=False)[json_resource]['count']

        ret = [count(self._project_id_neutron_to_vnc(pid) if pid else None)
               for pid in project_ids] if project_ids else [count(None)]
        return sum(ret)


class VMachineHandler(ResourceGetHandler, ResourceCreateHandler,
                      ResourceDeleteHandler):
    resource_create_method = 'virtual_machine_create'
    resource_list_method = 'virtual_machines_list'
    resource_get_method = 'virtual_machine_read'
    resource_delete_method = 'virtual_machine_delete'

    def ensure_vm_instance(self, instance_id):
        instance_name = instance_id
        instance_obj = vnc_api.VirtualMachine(instance_name)
        try:
            try:
                uuid.UUID(instance_id)
                instance_obj.uuid = instance_id
            except ValueError:
                # if instance_id is not a valid uuid, let
                # virtual_machine_create generate uuid for the vm
                pass
            self._resource_create(instance_obj)
        except vnc_exc.RefsExistError:
            instance_obj = self._resource_get(id=instance_obj.uuid)

        return instance_obj


class SGHandler(ResourceGetHandler, ResourceCreateHandler,
                ResourceDeleteHandler):
    resource_create_method = 'security_group_create'
    resource_list_method = 'security_groups_list'
    resource_get_method = 'security_group_read'
    resource_delete_method = 'security_group_delete'

    def _create_no_rule_sg(self):
        domain_obj = vnc_api.Domain(vnc_api_common.SG_NO_RULE_FQ_NAME[0])
        proj_obj = vnc_api.Project(vnc_api_common.SG_NO_RULE_FQ_NAME[1],
                                   domain_obj)
        sg_rules = vnc_api.PolicyEntriesType()
        id_perms = vnc_api.IdPermsType(
            enable=True,
            description="Security group with no rules",
            user_visible=False)
        sg_obj = vnc_api.SecurityGroup(
            name=vnc_api_common.SG_NO_RULE_NAME,
            parent_obj=proj_obj,
            security_group_entries=sg_rules,
            id_perms=id_perms)
        self._resource_create(sg_obj)
        return sg_obj
    # end _create_no_rule_sg

    def get_no_rule_security_group(self, create=True):
        try:
            sg_obj = self._resource_get(
                fq_name=vnc_api_common.SG_NO_RULE_FQ_NAME)
        except vnc_api.NoIdError:
            if create:
                sg_obj = self._create_no_rule_sg()
            else:
                sg_obj = None

        return sg_obj


class InstanceIpHandler(ResourceGetHandler, ResourceCreateHandler,
                        ResourceDeleteHandler, ResourceUpdateHandler):
    resource_create_method = 'instance_ip_create'
    resource_list_method = 'instance_ips_list'
    resource_get_method = 'instance_ip_read'
    resource_delete_method = 'instance_ip_delete'
    resource_update_method = 'instance_ip_update'

    def is_ip_addr_in_net_id(self, ip_addr, net_id):
        """Checks if ip address is present in net-id."""
        net_ip_list = [ipobj.get_instance_ip_address() for ipobj in
                       self._resource_list(back_ref_id=[net_id])]
        return ip_addr in net_ip_list

    def get_iip_obj(self, id):
        return self._resource_get(id=id)

    def get_iip_obj_list(self, **kwargs):
        return self._resource_list(**kwargs)

    def create_instance_ip(self, vn_obj, vmi_obj, ip_addr=None,
                           subnet_uuid=None, ip_family='v4'):
        ip_name = str(uuid.uuid4())
        ip_obj = vnc_api.InstanceIp(name=ip_name)
        ip_obj.uuid = ip_name
        if subnet_uuid:
            ip_obj.set_subnet_uuid(subnet_uuid)
        ip_obj.set_virtual_machine_interface(vmi_obj)
        ip_obj.set_virtual_network(vn_obj)
        if hasattr(ip_obj, 'set_instance_ip_family'):
            ip_obj.set_instance_ip_family(ip_family)
        if ip_addr:
            ip_obj.set_instance_ip_address(ip_addr)
        ip_id = self._resource_create(ip_obj)
        return ip_id

    def delete_iip_obj(self, iip_id):
        self._resource_delete(id=iip_id)
