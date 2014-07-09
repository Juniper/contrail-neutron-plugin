#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from eventlet import greenthread
from neutron.common import exceptions as n_exc
from neutron.extensions import loadbalancer
from neutron.extensions.loadbalancer import LoadBalancerPluginBase
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import LoadbalancerPool, LoadbalancerPoolType
from vnc_api.vnc_api import VirtualIp, VirtualIpType
from vnc_api.vnc_api import VncApi

def _get_tenant_id_for_create(context, resource):
    if context.is_admin and 'tenant_id' in resource:
        tenant_id = resource['tenant_id']
    elif ('tenant_id' in resource and
          resource['tenant_id'] != context.tenant_id):
        reason = 'Cannot create resource for another tenant'
        raise n_exc.AdminRequired(reason=reason)
    else:
        tenant_id = context.tenant_id
    return tenant_id

class LoadBalancerPluginDb(LoadBalancerPluginBase):

    _max_project_read_attempts = 3

    _virtual_ip_type_mapping = {
        'address': 'address',
        'protocol': 'protocol',
        'protocol_port': 'protocol_port',
        'connection_limit': 'connection_limit',
        'subnet_id': 'subnet_id',
        'admin_state': 'admin_state_up',
    }

    _loadbalancer_pool_type_mapping = {
        'admin_state': 'admin_state_up',
        'protocol': 'protocol',
        'loadbalancer_method': 'lb_method',
        'subnet_id': 'subnet_id'
    }

    def __init__(self):
        # TODO: parse configuration for api-server:port and auth
        self._api = VncApi()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

    def _apply_filter(self, resource, filters):
        if filters is None:
            return True
        for key, value in filters.iteritems():
            if key in resource and not resource[key] in value:
                return False
        return True

    def _project_read(self, project_id):
        """
        Reads the project from the api server. The project will be created
        it does not yet exist.
        """
        for i in range(self._max_project_read_attempts):
            try:
                return self._api.project_read(id=project_id)
            except NoIdError:
                pass
            greenthread.sleep(1)
        raise n_exc.TenantNetworksDisabled()

    def _get_resource_name(self, resource, parent, name, uuid):
        """
        Generate an unique name. This is display name if there are no
        conflicts or display_name + uuid
        """
        fq_name = list(parent.fq_name)
        fq_name.append(name)
        obj = self._api.fq_name_to_id(resource, fq_name)
        if obj is None:
            return name
        return name + '_' + uuid

    def _make_virtual_ip_properties(self, vip):
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
        change = False
        for key, mapping in self._virtual_ip_type_mapping.iteritems():
            if mapping not in vip:
                continue
            if getattr(props, key) != vip[mapping]:
                setattr(props, key, vip[mapping])
                change = True

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

    def _get_vip_pool_id(self, vip):
        pool_refs = vip.get_loadbalancer_pool_refs()
        if pool_refs is None:
            return None
        return pool_refs[0]['uuid']

    def _get_object_status(self, obj):
        id_perms = obj.get_id_perms()
        if id_perms and id_perms.enable:
            return constants.ACTIVE
        return constants.PENDING_DELETE

    def _get_object_description(self, obj):
        id_perms = obj.get_id_perms()
        if id_perms is None:
            return None
        return id_perms.description

    def _make_vip_dict(self, vip, fields=None):
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

    def _make_loadbalancer_pool_properties(self, pool):
        props = LoadbalancerPoolType()
        for key, mapping in self._loadbalancer_pool_type_mapping.iteritems():
            if mapping in pool:
                setattr(props, key, pool[mapping])
        return props

    def _make_pool_dict(self, pool, fields=None):
        res = {'id': pool.uuid,
               'tenant_id': pool.parent_uuid,
               'name': pool.display_name,
               'description': self._get_object_description(pool),
               'status': self._get_object_status(pool),
               }

        props = pool.get_loadbalancer_pool_properties()
        for key, mapping in self._loadbalancer_pool_type_mapping.iteritems():
            value = getattr(props, key)
            if value is not None:
                res[mapping] = value

        # TODO: report provider
        res['provider'] = 'lbaas'

        # vip_id
        vip_refs = pool.get_virtual_ip_back_refs()
        if vip_refs is not None:
            res['vip_id'] = vip_refs[0]['uuid']

        # members
        members = pool.get_loadbalancer_members()
        if members is not None:
            res['members'] = [member['uuid'] for member in members]

        # health_monitors
        hm_refs = pool.get_loadbalancer_healthmonitor_refs()
        if hm_refs is not None:
            res['health_monitors'] = [hm['uuid'] for hm in hm_refs]

        # TODO: health_monitor_status
        return self._fields(res, fields)

    def get_vips(self, context, filters=None, fields=None):
        """ Retrive the list of virtual-ips """

        def get_vip_dict(uuid, filters, fields):
            try:
                vip = self._api.virtual_ip_read(id=uuid)
            except NoIdError:
                return None
            res = self._make_vip_dict(vip, None)
            if not self._apply_filter(res, filters):
                return None
            return self._fields(res, fields)

        def isAuthorized(context, vip):
            return context.is_admin or \
                context.tenant_id == vip['tenant_id']

        response = []

        if filters and 'id' in filters:
            for v in filters['id']:
                res = get_vip_dict(v, filters, fields)
                if res is not None and isAuthorized(context, res):
                    response.append(res)
            return response

        parent_id = None
        if not context.is_admin:
            parent_id = context.tenant_id
        vip_list = self._api.virtual_ips_list(parent_id=parent_id)

        if 'virtual-ips' not in vip_list:
            return response

        for v in vip_list['virtual-ips']:
            res = get_vip_dict(v['uuid'], filters, fields)
            if res is not None:
                response.append(res)
        return response

    def get_vip(self, context, id, fields=None):
        try:
            vip = self._api.virtual_ip_read(id=id)
        except NoIdError:
            raise loadbalancer.VipNotFound(vip_id=id)
        if not context.is_admin and context.tenant_id != vip.parent_uuid:
            raise loadbalancer.VipNotFound(vip_id=id)
        return self._make_vip_dict(vip, fields)

    def create_vip(self, context, vip):
        """
        Create a VIP.
        """
        v = vip['vip']
        tenant_id = _get_tenant_id_for_create(context, v)

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
        props = self._make_virtual_ip_properties(v)
        id_perms = IdPermsType(uuid=uuid, enable=True,
                               description=v['description'])
        vip = VirtualIp(name, project, virtual_ip_properties=props,
                        id_perms=id_perms, display_name=v['name'])
        vip.uuid = uuid

        if pool:
            vip.set_loadbalancer_pool(pool)

        self._api.virtual_ip_create(vip)
        return self._make_vip_dict(vip)

    def update_vip(self, context, id, vip):
        try:
            vip_db = self._api.virtual_ip_read(id=id)
        except NoIdError:
            raise loadbalancer.VipNotFound(vip_id=id)

        id_perms = vip_db.get_id_perms()
        if not id_perms or not id_perms.enable:
            raise loadbalancer.StateInvalid(id=id,
                                            state=constants.PENDING_DELETE)

        v = vip['vip']
        if v:
            update = False
            props = vip_db.get_virtual_ip_properties()
            if self._update_virtual_ip_properties(props, id, v):
                vip_db.set_virtual_ip_properties(props)
                update = True

            if 'description' in v and id_perms.description != v['description']:
                id_perms.description = v['description']
                vip_db.set_id_perms(id_perms)
                update = True

            if 'pool_id' in v and \
                    self._get_vip_pool_id(vip_db) != v['pool_id']:
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
                update = True

            if update:
                self._api.virtual_ip_update(vip_db)

        return self._make_vip_dict(vip_db)

    def delete_vip(self, context, id):
        if not context.is_admin:
            try:
                vip = self._api.virtual_ip_read(id=id)
            except NoIdError:
                raise loadbalancer.VipNotFound(vip_id=id)
            if context.tenant_id != vip.parent_uuid:
                raise n_exc.NotAuthorized()

        # TODO: automatically delete virtual-machine-interface
        # TODO: possible exceptions: RefsExistError
        try:
            self._api.virtual_ip_delete(id=id)
        except NoIdError:
            raise loadbalancer.VipNotFound(vip_id=id)

    def get_pools(self, context, filters=None, fields=None):
        pass

    def get_pool(self, context, id, fields=None):
        pass

    def create_pool(self, context, pool):
        """
        Create a loadbalancer_pool object.
        """
        v = pool['pool']
        tenant_id = _get_tenant_id_for_create(context, v)

        project = self._project_read(project_id=tenant_id)

        uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('loadbalancer-pool', project,
                                       v['name'], uuid)
        props = self._make_loadbalancer_pool_properties(v)
        id_perms = IdPermsType(uuid=uuid, enable=True,
                               description=v['description'])
        pool = LoadbalancerPool(name, project,
                                loadbalancer_pool_properties=props,
                                id_perms=id_perms, display_name=v['name'])
        pool.uuid = uuid

        if v['health_monitors']:
            for hm in v['health_monitors']:
                try:
                    mon = self._api.loadbalancer_healthmonitor_read(id=hm)
                except NoIdError:
                    raise loadbalancer.HealthMonitorNotFound(monitor_id=hm)
                pool.add_loadbalancer_healthmonitor(mon)

        self._api.loadbalancer_pool_create(pool)
        return self._make_pool_dict(pool)

    def update_pool(self, context, id, pool):
        pass

    def delete_pool(self, context, id):
        pass

    def stats(self, context, pool_id):
        pass

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        pass

    def get_pool_health_monitor(self, context, id, pool_id, fields=None):
        pass

    def delete_pool_health_monitor(self, context, id, pool_id):
        pass

    def get_members(self, context, filters=None, fields=None):
        pass

    def get_member(self, context, id, fields=None):
        pass

    def create_member(self, context, member):
        pass

    def update_member(self, context, id, member):
        pass

    def delete_member(self, context, id):
        pass

    def get_health_monitors(self, context, filters=None, fields=None):
        pass

    def get_health_monitor(self, context, id, fields=None):
        pass

    def create_health_monitor(self, context, health_monitor):
        pass

    def update_health_monitor(self, context, id, health_monitor):
        pass

    def delete_health_monitor(self, context, id):
        pass
