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

import math
import operator
import uuid

from cfgm_common import exceptions as vnc_exc
import netaddr
from vnc_api import vnc_api

import contrail_res_handler as res_handler
import subnet_res_handler as subnet_handler

try:
    from oslo_log import log as logging
except ImportError:
    import logging

LOG = logging.getLogger(__name__)


class SubnetPoolMixin(object):

    _PREFIX_INFO = {4: {'max_prefixlen': 32,
                        'wildcard': '0.0.0.0',
                        'default_min_prefixlen': 8,
                        'quota_units': 32},
                    6: {'max_prefixlen': 128,
                        'wildcard': '::',
                        'default_min_prefixlen': 64,
                        # IPv6 quota measured in units of /64
                        'quota_units': 64}}

    def _extract_subnetpool_data(self, subnetpool_q, sp_info, context):
        default_prefixlen = subnetpool_q.get('default_prefixlen',
                                             sp_info.get_default_prefix_len())
        if not default_prefixlen:
            msg = 'default_prefixlen should be defined'
            self._raise_contrail_exception(
                'BadRequest', resource='subnetpool', msg=msg)

        shared = subnetpool_q.get('shared', False)
        if shared and not context['is_admin']:
            msg = 'Only admin can create shared subnetpool'
            self._raise_contrail_exception('BadRequest', resource='subnetpool',
                                           msg=msg)

        prefixes = subnetpool_q.get('prefixes')
        orig_prefixes = sp_info.get_prefixes()
        if not prefixes and not orig_prefixes:
            self._raise_contrail_exception('EmptySubnetPoolPrefixList')

        if prefixes and orig_prefixes:
            sp_prefixes = ['%s/%s' % (prefix.get_ip_prefix(),
                                      prefix.get_ip_prefix_len())
                           for prefix in orig_prefixes]
            orig_set = netaddr.IPSet(sp_prefixes)
            new_set = netaddr.IPSet(prefixes)
            if not orig_set.issubset(new_set):
                msg = ("Existing prefixes must be "
                       "a subset of the new prefixes")
                self._raise_contrail_exception(
                    'IllegalSubnetPoolPrefixUpdate', msg=msg)

            sp_prefixes.extend(prefixes)
            prefixes = sp_prefixes

        if prefixes:
            ip_version = self._get_ip_version(prefixes)
        else:
            ip_version = sp_info.get_ip_version()
            ip_version = int(ip_version[1])

        max_prefixlen = subnetpool_q.get('max_prefixlen',
                                         sp_info.get_max_prefix_len())
        if max_prefixlen:
            self._validate_max_prefixlen(max_prefixlen, ip_version)
        else:
            max_prefixlen = self._default_max_prefixlen(ip_version)

        min_prefixlen = subnetpool_q.get('min_prefixlen',
                                         sp_info.get_min_prefix_len())
        if min_prefixlen:
            self._validate_min_prefixlen(ip_version, min_prefixlen,
                                         max_prefixlen)
        else:
            min_prefixlen = self._default_min_prefixlen(ip_version)

        self._validate_default_prefixlen(min_prefixlen, max_prefixlen,
                                         default_prefixlen)

        default_quota = subnetpool_q.get('default_quota',
                                         sp_info.get_default_quota())
        sp_info.set_shared(shared)
        sp_info.set_default_prefix_len(default_prefixlen)
        sp_info.set_min_prefix_len(min_prefixlen)
        sp_info.set_max_prefix_len(max_prefixlen)
        sp_info.set_default_quota(default_quota)
        sp_info.set_ip_version('v' + str(ip_version))
        if prefixes:
            pool_prefixes = [self._validate_and_create_subnet_type(prefix)
                             for prefix in prefixes]
            sp_info.set_prefixes(pool_prefixes)
        return sp_info

    def _validate_and_create_subnet_type(self, prefix):
        cidr = netaddr.IPNetwork(prefix)
        pfx = str(cidr.network)
        pfx_len = int(cidr.prefixlen)
        return vnc_api.SubnetType(pfx, pfx_len)

    def _sp_obj_to_neutron_dict(self, sp_obj, fields=None):
        sp_q_dict = {}
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

        sp_q_dict['default_quota'] = sp_info.get_default_quota()
        sp_q_dict['shared'] = sp_info.get_shared()
        sp_prefixes = ['%s/%s' % (prefix.get_ip_prefix(),
                                  prefix.get_ip_prefix_len())
                       for prefix in sp_info.get_prefixes()]
        sp_q_dict['prefixes'] = sp_prefixes

        if fields:
            sp_q_dict = self._filter_res_dict(sp_q_dict, fields)

        return sp_q_dict

    def _get_ip_version(self, prefixes):
        ip_version = None
        for prefix in prefixes:
            if not ip_version:
                ip_version = netaddr.IPNetwork(prefix).version
            elif netaddr.IPNetwork(prefix).version != ip_version:
                self._raise_contrail_exception('PrefixVersionMismatch')
        return ip_version

    def _validate_min_prefixlen(self, ip_version, min_prefixlen,
                                max_prefixlen):
        if min_prefixlen < 0:
            self._raise_contrail_exception('UnsupportedMinSubnetPoolPrefix',
                                           prefix=min_prefixlen,
                                           version=4)
        if min_prefixlen > max_prefixlen:
            self._raise_contrail_exception(
                'IllegalSubnetPoolPrefixBounds', prefix_type='min_prefixlen',
                prefixlen=min_prefixlen, base_prefix_type='max_prefixlen',
                base_prefixlen=max_prefixlen)

    def _validate_max_prefixlen(self, max_prefixlen, ip_version):
        max = self._PREFIX_INFO[ip_version]['max_prefixlen']
        if max_prefixlen > max:
            self._raise_contrail_exception(
                'IllegalSubnetPoolPrefixBounds', prefix_type='max_prefixlen',
                prefixlen=max_prefixlen, base_prefix_type='ip_version_max',
                base_prefixlen=max)

    def _validate_default_prefixlen(self, min_prefixlen, max_prefixlen,
                                    default_prefixlen):
        if default_prefixlen < min_prefixlen:
            self._raise_contrail_exception(
                'IllegalSubnetPoolPrefixBounds',
                prefix_type='default_prefixlen',
                prefixlen=default_prefixlen,
                base_prefix_type='min_prefixlen',
                base_prefixlen=min_prefixlen)

        if default_prefixlen > max_prefixlen:
            self._raise_contrail_exception(
                'IllegalSubnetPoolPrefixBounds',
                prefix_type='default_prefixlen',
                prefixlen=default_prefixlen,
                base_prefix_type='max_prefixlen',
                base_prefixlen=max_prefixlen)

    def _default_max_prefixlen(self, ip_version):
        return self._PREFIX_INFO[ip_version]['max_prefixlen']

    def _default_min_prefixlen(self, ip_version):
        return self._PREFIX_INFO[ip_version]['default_min_prefixlen']

    def get_subnetpool_quota_unit(self, ip_version):
        return self._PREFIX_INFO[ip_version]['quota_units']


class SubnetPoolCreateHandler(res_handler.ResourceCreateHandler,
                              SubnetPoolMixin):
    resource_create_method = 'subnet_pool_create'

    def _create_subnetpool_obj(self, context, subnetpool_q):
        proj_id = self._project_id_neutron_to_vnc(subnetpool_q['tenant_id'])
        proj_obj = self._project_read(proj_id=proj_id)
        sp_info = vnc_api.SubnetPoolType()
        sp_info = self._extract_subnetpool_data(subnetpool_q, sp_info, context)
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
        try:
            sp_obj = self._resource_get(id=subnetpool_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception(
                'SubnetPoolNotFound', subnetpool_id=subnetpool_id,
                resource='subnetpool')

        sp_info = self._extract_subnetpool_data(subnetpool_q,
                                                sp_obj.get_subnet_pool_data(),
                                                context)
        sp_obj.set_subnet_pool_data(sp_info)
        self._resource_update(sp_obj)
        sp_obj = self._resource_get(id=subnetpool_id)
        return self._sp_obj_to_neutron_dict(sp_obj)


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
            if 'id' in filters and not self._filters_is_present(
                    filters, 'id', sp_obj.uuid):
                continue

            if 'name' in filters and not self._filters_is_present(
                    filters, 'name', sp_obj.display_name):
                continue

            sp_q_dict = self._sp_obj_to_neutron_dict(sp_obj,
                                                     fields=fields)
            if sp_q_dict:
                ret_list.append(sp_q_dict)
        return ret_list


class SubnetPoolDeleteHandler(res_handler.ResourceDeleteHandler):
    resource_delete_method = 'subnet_pool_delete'

    def resource_delete(self, context, subnetpool_id):
        try:
            sp_obj = self._resource_get(id=subnetpool_id)

        except vnc_exc.NoIdError:
            self._raise_contrail_exception('SubnetPoolNotFound',
                                           subnetpool_id=subnetpool_id)

        if sp_obj.get_virtual_network_back_refs():
            reason = 'Subnetpool is still in use'
            self._raise_contrail_exception('SubnetPoolDeleteError',
                                           reason=reason)

        self._resource_delete(id=subnetpool_id)


class SubnetPoolHandler(SubnetPoolCreateHandler, SubnetPoolDeleteHandler,
                        SubnetPoolGetHandler, SubnetPoolUpdateHandler):
    pass


class SubnetPoolAllocator(object):
    """SubnetPool Allocator class.

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

    def _num_quota_units_in_prefixlen(self, prefixlen, quota_unit):
        return math.pow(2, quota_unit - prefixlen)

    def _allocations_used_by_tenant(self, quota_unit, vn_objs):
        allocated_prefixes = self._get_allocated_prefixes(vn_objs)
        value = 0
        for prefix in allocated_prefixes:
            prefixlen = netaddr.IPNetwork(prefix).prefixlen
            value += self._num_quota_units_in_prefixlen(prefixlen,
                                                        quota_unit)
        return value

    def _check_subnetpool_quota(self, quota_unit, quota, prefix_len, vn_objs):
        used = self._allocations_used_by_tenant(quota_unit, vn_objs)
        requested_units = self._num_quota_units_in_prefixlen(prefix_len,
                                                             quota_unit)
        if used + requested_units > quota:
            res_handler.ContrailResourceHandler._raise_contrail_exception(
                'SubnetPoolQuotaExceeded')

    def allocate_cidr_from_subnetpool(self, sp_obj, requested_prefix_len,
                                      vn_objs=[], requested_cidr=None):
        subnetpool_default_quota = (
            sp_obj.get_subnet_pool_data().get_default_quota())
        if subnetpool_default_quota:
            if sp_obj.get_subnet_pool_data().get_ip_version() == 'v4':
                # IPv4 quota measured in units of /32
                quota_unit = 32
            else:
                # IPv6 quota measured in units of /64
                quota_unit = 64
            self._check_subnetpool_quota(quota_unit, subnetpool_default_quota,
                                         requested_prefix_len,
                                         vn_objs)

        available_prefixes = self._get_available_prefixes(sp_obj, vn_objs)

        if not requested_cidr:
            for prefix in available_prefixes:
                if requested_prefix_len >= prefix.prefixlen:
                    subnet = next(prefix.subnet(requested_prefix_len))
                    return subnet.cidr
            msg = ("Insufficient prefix space to allocate subnet size /%s")
            res_handler.ContrailResourceHandler._raise_contrail_exception(
                'SubnetAllocationError',
                reason=msg % (str(requested_prefix_len)))

        cidr = netaddr.IPNetwork(requested_cidr)
        matched = netaddr.all_matching_cidrs(cidr, available_prefixes)
        if len(matched) is 1 and matched[0].prefixlen <= cidr.prefixlen:
            return requested_cidr

        msg = ("Cannot allocate requested subnet from the available "
               "set of prefixes")
        res_handler.ContrailResourceHandler._raise_contrail_exception(
            'SubnetAllocationError', reason=msg)
