#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from eventlet import greenthread
from neutron.common import exceptions as n_exc
from neutron.extensions import loadbalancer
from neutron.extensions.loadbalancer import LoadBalancerPluginBase
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
import logging

from vnc_api.vnc_api import VncApi
from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import VirtualIp, VirtualIpType

LOG = logging.getLogger(__name__)


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


class LoadBalancerPlugin(LoadBalancerPluginBase):
    supported_extension_aliases = ["lbaas"]

    _max_project_read_attempts = 3

    def __init__(self):
        # TODO: parse configuration for api-server:port and auth
        self._api = VncApi()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

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

    def get_plugin_description(self):
        return "OpenContrail LoadBalancer Service Plugin"

    def _make_virtual_ip_properties(self, vip):
        props = VirtualIpType()
        props.address = vip['address']
        props.protocol = vip['protocol']
        props.protocol_port = vip['protocol_port']
        props.connection_limit = vip['connection_limit']
        props.subnet_id = vip['subnet_id']
        props.admin_state = vip['admin_state_up']
        sp = vip['session_persistence']
        if sp is not None:
            props.persistence_type = sp['type']
            if 'cookie_name' in sp:
                props.persistence_cookie_name = sp['cookie_name']
        return props

    def _make_vip_dict(self, vip, fields=None):
        def get_pool_id(vip):
            pool_refs = vip.get_loadbalancer_pool_refs()
            if pool_refs is None:
                return None
            return pool_refs[0]['uuid']

        def get_vmi_uuid(vmi):
            if vmi is None:
                return None
            return vmi.uuid

        def get_description(vid):
            id_perms = vip.get_id_perms()
            if id_perms is None:
                return None
            return id_perms.description

        def get_status(vip):
            id_perms = vip.get_id_perms()
            if id_perms and id_perms.enable:
                return constants.ACTIVE
            return constants.PENDING_DELETE

        vmi = None
        vmi_list = vip.get_virtual_machine_interface_refs()
        if vmi_list:
            vmi = self._api.virtual_machine_interface_read(
                id=vmi_list[0]['uuid'])

        props = vip.get_virtual_ip_properties()
        res = {'id': vip.uuid,
               'tenant_id': vip.parent_uuid,
               'name': vip.display_name,
               'description': get_description(vip),
               'subnet_id': props.subnet_id,
               'address': props.address,
               'port_id': get_vmi_uuid(vmi),
               'protocol_port': props.protocol_port,
               'protocol': props.protocol,
               'pool_id': get_pool_id(vip),
               'session_persistence': None,
               'connection_limit': props.connection_limit,
               'admin_state_up': props.admin_state,
               'status': get_status(vip)}

        if props.persistence_type:
            sp = {'type': props.persistence_type}
            if props.persistence_type == 'APP_COOKIE':
                sp['cookie_name'] = props.persistence_cookie_name
            res['session_persistence'] = sp

        return self._fields(res, fields)

    def get_vips(self, context, filters=None, fields=None):
        pass

    def get_vip(self, context, id, fields=None):
        pass

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
        pass

    def delete_vip(self, context, id):
        pass

    def get_pools(self, context, filters=None, fields=None):
        pass

    def get_pool(self, context, id, fields=None):
        pass

    def create_pool(self, context, pool):
        pass

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
