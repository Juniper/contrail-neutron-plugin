#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import VirtualIp, VirtualIpType

from resource_manager import ResourceManager


class VirtualIpManager(ResourceManager):
    _virtual_ip_type_mapping = {
        'address': 'address',
        'protocol': 'protocol',
        'protocol_port': 'protocol_port',
        'connection_limit': 'connection_limit',
        'subnet_id': 'subnet_id',
        'admin_state': 'admin_state_up',
    }

    @property
    def property_type_mapping(self):
        return self._virtual_ip_type_mapping

    def make_properties(self, vip):
        props = VirtualIpType()
        for key, mapping in self._virtual_ip_type_mapping.iteritems():
            if mapping in vip:
                setattr(props, key, vip[mapping])

        sp = vip['session_persistence']
        if sp is not None:
            props.persistence_type = sp['type']
            if 'cookie_name' in sp:
                props.persistence_cookie_name = sp['cookie_name']
        return props

    def _get_vip_pool_id(self, vip):
        pool_refs = vip.get_loadbalancer_pool_refs()
        if pool_refs is None:
            return None
        return pool_refs[0]['uuid']

    def make_dict(self, vip, fields=None):
        def get_vmi_uuid(vmi):
            if vmi is None:
                return None
            return vmi.uuid

        vmi = None
        vmi_list = vip.get_virtual_machine_interface_refs()
        if vmi_list:
            vmi = self._api.virtual_machine_interface_read(
                id=vmi_list[0]['uuid'])

        props = vip.get_virtual_ip_properties()
        res = {'id': vip.uuid,
               'tenant_id': vip.parent_uuid,
               'name': vip.display_name,
               'description': self._get_object_description(vip),
               'subnet_id': props.subnet_id,
               'address': props.address,
               'port_id': get_vmi_uuid(vmi),
               'protocol_port': props.protocol_port,
               'protocol': props.protocol,
               'pool_id': self._get_vip_pool_id(vip),
               'session_persistence': None,
               'connection_limit': props.connection_limit,
               'admin_state_up': props.admin_state,
               'status': self._get_object_status(vip)}

        if props.persistence_type:
            sp = {'type': props.persistence_type}
            if props.persistence_type == 'APP_COOKIE':
                sp['cookie_name'] = props.persistence_cookie_name
            res['session_persistence'] = sp

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.virtual_ip_read(id=id)

    def resource_list(self, tenant_id=None):
        return self._api.virtual_ips_list(parent_id=tenant_id)

    def resource_update(self, obj):
        return self._api.virtual_ip_update(obj)

    def resource_delete(self, id):
        return self._api.virtual_ip_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancer.VipNotFound(vip_id=id)

    @property
    def neutron_name(self):
        return "vip"

    @property
    def resource_name_plural(self):
        return "virtual-ips"

    def create(self, context, vip):
        """
        Create a VIP.
        """
        v = vip['vip']
        tenant_id = self._get_tenant_id_for_create(context, v)

        project = self._project_read(project_id=tenant_id)

        if v['pool_id']:
            try:
                pool = self._api.loadbalancer_pool_read(id=v['pool_id'])
            except NoIdError:
                raise loadbalancer.PoolNotFound(pool_id=v['pool_id'])
            project_id = pool.parent_uuid
            if tenant_id != project_id:
                raise n_exc.NotAuthorized()
            # TODO: check that the pool has no vip configured
            # if pool.protocol != v['protocol']:
            #     raise loadbalancer.ProtocolMismatch(
            #         vip_proto=v['protocol'], pool_proto=pool.protocol)
        else:
            pool = None

        uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('virtual-ip', project, v['name'], uuid)
        props = self.make_properties(v)
        id_perms = IdPermsType(uuid=uuid, enable=True,
                               description=v['description'])
        vip = VirtualIp(name, project, virtual_ip_properties=props,
                        id_perms=id_perms, display_name=v['name'])
        vip.uuid = uuid

        if pool:
            vip.set_loadbalancer_pool(pool)

        self._api.virtual_ip_create(vip)
        return self.make_dict(vip)

    def _update_virtual_ip_properties(self, props, id, vip):
        """
        Update virtual ip properties and return True if the have been
        modified
        """
        # according to the spec:
        # status, subnet_id, address, port and protocol are immutable
        immutable = ['address', 'protocol', 'protocol_port', 'subnet_id']
        for field in immutable:
            if field not in vip:
                continue
            if getattr(props, field) != vip[field]:
                msg = 'Attribute %s in vip %s is immutable' % (field, id)
                raise n_exc.BadRequest(resource='vip', msg=msg)

        # update
        change = self.update_properties_subr(props, vip)

        if 'session_persistence' in vip:
            sp = vip['session_persistence']
            if props.persistence_type != sp['type']:
                props.persistence_type = sp['type']
                change = True
            if 'cookie_name' in sp and \
                    props.persistence_cookie_name != sp['cookie_name']:
                props.persistence_cookie_name != sp['cookie_name']
                change = True

        return change

    def update_properties(self, vip_db, id, v):
        props = vip_db.get_virtual_ip_properties()
        if self._update_virtual_ip_properties(props, id, v):
            vip_db.set_virtual_ip_properties(props)
            return True
        return False

    def update_object(self, vip_db, id, v):
        if 'pool_id' in v and self._get_vip_pool_id(vip_db) != v['pool_id']:
            try:
                pool = self._api.loadbalancer_pool_read(id=v['pool_id'])
            except NoIdError:
                raise loadbalancer.PoolNotFound(pool_id=v['pool_id'])
            if vip_db.parent_uuid != pool.parent_uuid:
                raise n_exc.NotAuthorized()
            # TODO: check that the pool has no vip configured
            # TODO: check that the protocol matches
            # TODO: check that the pool is in valid state
            vip_db.set_localbalancer_pool(pool)
            return True

        return False
