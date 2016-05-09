#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid

from neutron_lbaas.extensions import loadbalancerv2
try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils

from neutron.common import exceptions as n_exc

from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import LoadbalancerMember, LoadbalancerMemberType

from .. resource_manager import ResourceManager


class LoadbalancerMemberManager(ResourceManager):
    _loadbalancer_member_type_mapping = {
        'admin_state': 'admin_state_up',
        'status': 'status',
        'protocol_port': 'protocol_port',
        'weight': 'weight',
        'address': 'address',
    }

    @property
    def property_type_mapping(self):
        return self._loadbalancer_member_type_mapping

    def make_properties(self, member):
        props = LoadbalancerMemberType()
        for key, mapping in self._loadbalancer_member_type_mapping.iteritems():
            if mapping in member:
                setattr(props, key, member[mapping])
        return props

    def _get_member_pool_id(self, member):
        pool_uuid = member.parent_uuid
        return pool_uuid

    def make_dict(self, member, fields=None):
        res = {'id': member.uuid,
               'name': member.name,
               'pool_id': member.parent_uuid,
               'status': self._get_object_status(member)}

        try:
            pool = self._api.loadbalancer_pool_read(id=member.parent_uuid)
            res['tenant_id'] = pool.parent_uuid.replace('-', '')
        except NoIdError:
            pass

        props = member.get_loadbalancer_member_properties()
        for key, mapping in self._loadbalancer_member_type_mapping.iteritems():
            value = getattr(props, key, None)
            if value is not None:
                res[mapping] = value

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.loadbalancer_member_read(id=id)

    def resource_list(self, tenant_id=None):
        """ In order to retrive all the members for a specific tenant
        the code iterates through all the pools.
        """
        if tenant_id is None:
            return self._api.loadbalancer_members_list()

        pool_list = self._api.loadbalancer_pools_list(tenant_id)
        if 'loadbalancer-pools' not in pool_list:
            return {}

        member_list = []
        for pool in pool_list['loadbalancer-pools']:
            pool_members = self._api.loadbalancer_members_list(
                parent_id=pool['uuid'])
            if 'loadbalancer-members' in pool_members:
                member_list.extend(pool_members['loadbalancer-members'])

        response = {'loadbalancer-members': member_list}
        return response

    def get_resource(self, context, id, pool_id, fields=None):
        res = super(LoadbalancerMemberManager, self).get_resource(context, id)
        if res and res['pool_id'] != pool_id:
            raise loadbalancerv2.MemberNotFoundForPool(member_id=res['id'],
                                                       pool_id=res['pool_id'])
        return self._fields(res, fields)

    def get_collection(self, context, pool_id, filters=None, fields=None):
        """ Optimize the query for members in a pool.
        """
        member_list = []
        pool_members = self._api.loadbalancer_members_list(
                parent_id=pool_id)
        if 'loadbalancer-members' in pool_members:
            member_list.extend(pool_members['loadbalancer-members'])

        response = []
        for m in member_list:
            res = self._get_resource_dict(m['uuid'], filters, fields)
            if res is not None and self._is_authorized(context, res):
                response.append(res)
        return response

    def resource_update(self, obj):
        return self._api.loadbalancer_member_update(obj)

    def resource_delete(self, id):
        return self._api.loadbalancer_member_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

    def get_exception_inuse(self, id=None):
        pass

    @property
    def neutron_name(self):
        return "member"

    @property
    def resource_name_plural(self):
        return "loadbalancer-members"

    def create(self, context, pool_id, member):
        """
        Create a loadbalancer_member object.
        """
        m = member['member']
        try:
            pool = self._api.loadbalancer_pool_read(id=pool_id)
        except NoIdError:
            raise loadbalancerv2.EntityNotFound(name='Pool', id=pool_id)

        tenant_id = self._get_tenant_id_for_create(context, m)
        if str(uuid.UUID(tenant_id)) != pool.parent_uuid:
            raise n_exc.NotAuthorized()

        obj_uuid = uuidutils.generate_uuid()
        props = self.make_properties(m)
        id_perms = IdPermsType(enable=True)

        member_db = LoadbalancerMember(
            obj_uuid, pool, loadbalancer_member_properties=props,
            id_perms=id_perms)
        member_db.uuid = obj_uuid

        self._api.loadbalancer_member_create(member_db)
        return self.make_dict(member_db)

    def update_properties(self, member_db, id, m):
        props = member_db.get_loadbalancer_member_properties()
        if self.update_properties_subr(props, m):
            member_db.set_loadbalancer_member_properties(props)
            return True
        return False

    def delete(self, context, id, pool_id):
        try:
            member = self._api.loadbalancer_member_read(id=id)
        except NoIdError:
            raise loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

        try:
            pool = self._api.loadbalancer_pool_read(id=pool_id)
        except NoIdError:
            raise loadbalancerv2.EntityNotFound(name='Pool',
                                                id=pool_id)
        if id not in [member['uuid'] for member in
           pool.get_loadbalancer_members() or []]:
            raise loadbalancerv2.MemberNotFoundForPool(member_id=id,
                                                       pool_id=pool_id)
        super(LoadbalancerMemberManager, self).delete(context, id)

    def update_object(self, member_db, id, m):
        pool_id = member_db.parent_uuid
        try:
            pool = self._api.loadbalancer_pool_read(id=pool_id)
        except NoIdError:
            raise loadbalancerv2.EntityNotFound(name='Pool',
                                                id=pool_id)
        db_props = member_db.get_loadbalancer_member_properties()
        members = pool.get_loadbalancer_members()
        for member in members or []:
            if id == member['uuid']:
                continue
            member_obj = self._api.loadbalancer_member_read(id=member['uuid'])
            props = member_obj.get_loadbalancer_member_properties()
            if ((props.get_address() == db_props.get_address()) and
                (props.get_protocol_port() == db_props.get_protocol_port())):
                raise loadbalancerv2.MemberExists(
                    address=props.get_address(),
                    port=props.get_protocol_port(),
                    pool=pool_id)
        return True
