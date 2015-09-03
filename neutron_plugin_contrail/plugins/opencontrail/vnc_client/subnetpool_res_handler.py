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
# @author: Numan Siddique, RedHat 

import operator
import uuid

from cfgm_common import exceptions as vnc_exc
import contrail_res_handler as res_handler
import netaddr
import subnet_res_handler as subnet_handler
from vnc_api import vnc_api

try:
    from oslo_log import log as logging
except ImportError:
    import logging

LOG = logging.getLogger(__name__)


class SubnetPoolMixin(object):

    def _subnetpool_neutron_to_vnc(self, subnetpool_q, subnetpool_vnc):
        pass

    def _validate_and_create_subnet_type(self, prefix):
        cidr = netaddr.IPNetwork(prefix)
        pfx = str(cidr.network)
        pfx_len = int(cidr.prefixlen)
        return vnc_api.SubnetType(pfx, pfx_len)

    def _sp_obj_to_neutron_dict(self, sp_obj, fields=None):
        sp_q_dict= {}
        sp_q_dict['id'] = sp_obj.uuid
        sp_q_dict['tenant_id'] = self._project_id_vnc_to_neutron(
            sp_obj.parent_uuid)
        if not sp_obj.display_name:
            sp_q_dict['name'] = sp_obj.get_fq_name()[-1]
        else:
            sp_q_dict['name'] = sp_obj.display_name
        sp_q_dict['address_scope_id'] = ''
        sp_info = sp_obj.get_subnet_pool_data()
        if not sp_info:
            return {}

        sp_q_dict['ip_version'] = sp_info.get_ip_version()[1]
        sp_q_dict['min_prefixlen'] = sp_info.get_min_prefix_len()
        sp_q_dict['default_prefixlen'] = sp_info.get_default_prefix_len()
        sp_q_dict['max_prefixlen'] = sp_info.get_max_prefix_len()

        sp_q_dict['default_quota'] = None
        sp_prefixes = ['%s/%s' % (prefix.get_ip_prefix(),
                                  prefix.get_ip_prefix_len())
                       for prefix in sp_info.get_prefixes()]
        sp_q_dict['prefixes'] = sp_prefixes

        if fields:
            sp_q_dict = self._filter_res_dict(sp_q_dict, fields)

        return sp_q_dict

class SubnetPoolCreateHandler(res_handler.ResourceCreateHandler,
                              SubnetPoolMixin):
    resource_create_method = 'subnet_pool_create'

    def _create_subnetpool_obj(self, context, subnetpool_q):
        proj_id = self._project_id_neutron_to_vnc(subnetpool_q['tenant_id'])
        proj_obj = self._project_read(proj_id=proj_id)
        sp_info = vnc_api.SubnetPoolType()
        default_prefixlen = subnetpool_q.get('default_prefixlen')
        if not default_prefixlen:
            msg = 'default_prefixlen should be defined'
            self._raise_contrail_exception(
                'BadRequest', resource='subnetpool', msg=msg)
        shared = subnetpool_q.get('shared', False)
        if shared and not context['is_admin']:
            msg = 'Only admin can create shared subnetpool'
            self._raise_contrail_exception('BadRequest', resource='subnetpool',
                                           msg=msg)

        sp_info.set_shared(shared)
        sp_info.set_default_prefix_len(default_prefixlen)
        sp_info.set_min_prefix_len(subnetpool_q.get('min_prefixlen', 8))
        sp_info.set_max_prefix_len(subnetpool_q.get('max_prefixlen', 32))

        ip_version = subnetpool_q.get('ip_version', '4')
        if ip_version != '4' and ip_version != '6':
            msg = 'Invalid ip version'
            self._raise_contrail_exception(
                'BadRequest', resource='subnetpool', msg=msg)
        sp_info.set_ip_version('v' + ip_version)
        pool_prefixes = [self._validate_and_create_subnet_type(prefix)
                         for prefix in subnetpool_q.get('prefixes', [])]
        sp_info.set_prefixes(pool_prefixes)
        sp_uuid = str(uuid.uuid4())
        sp_name = subnetpool_q.get('name', sp_uuid)
        sp_obj = vnc_api.SubnetPool(name=sp_name, parent_obj=proj_obj,
                                    subnet_pool_data=sp_info)
        return sp_obj

    def resource_create(self, context, subnetpool_q):
        sp_obj = self._create_subnetpool_obj(context, subnetpool_q)
        try:
            sp_uuid = self._resource_create(sp_obj)
        except vnc_exc.RefsExistError:
            msg = 'Error creating subnetpool'
            self._raise_contrail_exception('BadRequest',
                                           resource='subnetpool', msg=msg)

        sp_obj = self._resource_get(id=sp_uuid)
        return self._sp_obj_to_neutron_dict(sp_obj)

class SubnetPoolUpdateHandler(res_handler.ResourceUpdateHandler,
                              SubnetPoolMixin):
    resource_update_method = 'subnet_pool_update'

    def resource_update(self, context, subnetpool_id, subnetpool_q):
        return {}


class SubnetPoolGetHandler(res_handler.ResourceGetHandler,
                           SubnetPoolMixin):
    resource_list_method = 'subnet_pools_list'
    resource_get_method = 'subnet_pool_read'

    def get_sp_obj(self, sp_id, fields=None):
        return self._resource_get(id=sp_id, fields=fields)

    def resource_get(self, context, subnetpool_id, fields=None):
        try:
            sp_obj = self._resource_get(id=subnetpool_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'SubnetPoolNotFound', subnetpool_id=subnetpool_id,
                resource='subnetpool')

        return self._sp_obj_to_neutron_dict(sp_obj, fields=fields)

    def resource_count(self, context, filters):
        count = self._resource_count_optimized(filters)
        if count is not None:
            return count

        sps_info = self.resource_list(context=None, filters=filters)
        return len(sps_info)

    def resource_list(self, context, filters, fields=None):
        proj_ids = None
        ret_list = []
        if filters is None:
            filters = {}

        if 'tenant_id' in filters:
            proj_ids = self._validate_project_ids(
                context, filters['tenant_id'])
        else:
            if not context['is_admin']:
                proj_ids = [self._project_id_neutron_to_vnc(context['tenant'])]

        obj_uuids = filters.get('id')
        sp_objs = self._resource_list(obj_uuids=obj_uuids, parent_id=proj_ids,
                                      back_refs=True)
        for sp_obj in sp_objs:
            sp_q_dict = self._sp_obj_to_neutron_dict(sp_obj,
                                                     fields=fields)
            if sp_q_dict:
                ret_list.append(sp_q_dict)
        return ret_list


class SubnetPoolDeleteHandler(res_handler.ResourceDeleteHandler):
    resource_delete_method = 'subnet_pool_delete'

    def resource_delete(self, context, subnetpool_id):
        try:
            self._resource_delete(id=subnetpool_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception('SubnetPoolNotFound',
                                           subnetpool_id=subnetpool_id)


class SubnetPoolHandler(SubnetPoolCreateHandler, SubnetPoolDeleteHandler,
                        SubnetPoolGetHandler, SubnetPoolUpdateHandler):
    pass


class SubnetPoolAllocator(object):
    """ SubnetPool Allocator class.

    The logic to allocate cidr from subnetpools is taken
    from neutron/ipam/subnet_alloc.py SubnetAllocator.allocate_subnet().
    """

    def __init__(self):
        pass

    def _get_sp_prefixes(self, sp_obj):
        return ['%s/%s' % (prefix.ip_prefix, prefix.ip_prefix_len)
                for prefix in sp_obj.get_subnet_pool_data().get_prefixes()]

    def _get_allocated_prefixes(self, vn_objs):
        allocated_prefixes = []
        for vn_obj in vn_objs:
            vn_subnets = subnet_handler.SubnetHandler.get_vn_subnets(vn_obj)
            vn_cidrs = [subnet['cidr'] for subnet in vn_subnets]
            allocated_prefixes.extend(vn_cidrs)
        return allocated_prefixes

    def _get_available_prefixes(self, sp_obj, vn_objs):
        sp_prefixes = self._get_sp_prefixes(sp_obj)
        allocated_prefixes = self._get_allocated_prefixes(vn_objs)
        prefix_set = netaddr.IPSet(iterable=sp_prefixes)
        allocation_set = netaddr.IPSet(iterable=allocated_prefixes)
        available_set = prefix_set.difference(allocation_set)
        available_set.compact()
        return sorted(available_set.iter_cidrs(),
                      key=operator.attrgetter('prefixlen'),
                      reverse=True)

    def allocate_cidr_from_subnetpool(self, sp_obj, requested_prefix_len,
                                      vn_objs=[], requested_cidr=None):

        available_prefixes =  self._get_available_prefixes(sp_obj, vn_objs)

        if not requested_cidr:
            for prefix in available_prefixes:
                if requested_prefix_len >= prefix.prefixlen:
                    subnet = next(prefix.subnet(requested_prefix_len))
                    return subnet.cidr
            msg = _("Insufficient prefix space to allocate subnet size /%s")
            res_handler.ContrailResourceHandler._raise_contrail_exception(
                'SubnetAllocationError',
                reason=msg % (str(requested_prefix_len)))

        cidr = netaddr.IPNetwork(requested_cidr)
        matched = netaddr.all_matching_cidrs(cidr, available_prefixes)
        if len(matched) is 1 and matched[0].prefixlen <= cidr.prefixlen:
            return requested_cidr

        msg = _("Cannot allocate requested subnet from the available "
                    "set of prefixes")
        res_handler.ContrailResourceHandler._raise_contrail_exception(
                'SubnetAllocationError', reason=msg)
