#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import LoadbalancerMember, LoadbalancerMemberType

from resource_manager import ResourceManager


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

    def make_dict(self, member, fields=None):
        res = {'id': member.uuid,
               'pool_id': member.parent_uuid,
               'status': self._get_object_status(member)}

        try:
            pool = self._api.loadbalancer_pool_read(id=member.parent_uuid)
            res['tenant_id'] = pool.parent_uuid
        except NoIdError:
            pass

        props = member.get_loadbalancer_member_properties()
        for key, mapping in self._loadbalancer_member_type_mapping.iteritems():
            value = getattr(props, key)
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
        for pool in pool_list:
            pool_members = self._api.loadbalancer_members_list(
                parent_id=pool['uuid'])
            if 'loadbalancer-members' in pool_members:
                member_list.expand(pool_members['loadbalancer-members'])

        response = {'loadbalancer-members': member_list}
        return response

    def get_collection(self, context, filters=None, fields=None):
        """ Optimize the query for members in a pool.
        """
        if 'pool_id' not in filters:
            return super(LoadbalancerMemberManager, self).get_collection(
                context, filters, fields)

        member_list = []
        for pool in filters['pool_id']:
            pool_members = self._api.loadbalancer_members_list(
                parent_id=pool)
            if 'loadbalancer-members' in pool_members:
                member_list.expand(pool_members['loadbalancer-members'])

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
        return loadbalancer.MemberNotFound(member_id=id)

    @property
    def neutron_name(self):
        return "member"

    @property
    def resource_name_plural(self):
        return "loadbalancer-members"

    def create(self, context, member):
        """
        Create a loadbalancer_member object.
        """
        m = member['member']
        try:
            pool = self._api.loadbalancer_pool_read(id=m['pool_id'])
        except NoIdError:
            raise loadbalancer.PoolNotFound(pool_id=m['pool_id'])

        tenant_id = self._get_tenant_id_for_create(context, m)
        if tenant_id != pool.parent_uuid:
            raise n_exc.NotAuthorized()

        uuid = uuidutils.generate_uuid()
        props = self.make_properties(m)
        id_perms = IdPermsType(uuid=uuid, enable=True)

        member_db = LoadbalancerMember(
            uuid, pool, loadbalancer_member_properties=props,
            id_perms=id_perms)
        member_db.uuid = uuid

        self._api.loadbalancer_member_create(member_db)
        return self.make_dict(member_db)

    def update_properties(self, member_db, id, m):
        props = member_db.get_loadbalancer_member_properties()
        if self.update_properties_subr(props, m):
            member_db.set_loadbalancer_member_properties(props)
            return True
        return False
