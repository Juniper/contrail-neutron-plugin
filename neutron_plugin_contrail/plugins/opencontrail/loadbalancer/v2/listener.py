#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
try:
    from neutron.api.v2.attributes import ATTR_NOT_SPECIFIED
except:
    from neutron_lib.constants import ATTR_NOT_SPECIFIED
try:
    from neutron.common.exceptions import NotAuthorized
except ImportError:
    from neutron_lib.exceptions import NotAuthorized
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest
from neutron_lbaas.extensions import loadbalancerv2

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils

from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import InstanceIp, VirtualMachineInterface
from vnc_api.vnc_api import SecurityGroup
from vnc_api.vnc_api import LoadbalancerListener, LoadbalancerListenerType

from .. resource_manager import ResourceManager, EntityInUse
from .. import utils
import uuid


class ListenerManager(ResourceManager):
    _listener_type_mapping = {
        'protocol': 'protocol',
        'protocol_port': 'protocol_port',
        'admin_state': 'admin_state_up',
        'connection_limit': 'connection_limit',
        'default_tls_container': 'default_tls_container_ref',
        'sni_containers': 'sni_container_refs',
    }

    @property
    def property_type_mapping(self):
        return self._listener_type_mapping

    def make_properties(self, lb):
        props = LoadbalancerListenerType()
        for key, mapping in self._listener_type_mapping.iteritems():
            if mapping in lb and lb[mapping] != ATTR_NOT_SPECIFIED:
                setattr(props, key, lb[mapping])
        return props

    def _get_loadbalancers(self, ll):
        loadbalancers = []
        lb = {}
        lb_refs = ll.get_loadbalancer_refs()
        if lb_refs is None:
            return None
        lb['id'] = lb_refs[0]['uuid']
        loadbalancers.append(lb)
        return loadbalancers

    def make_dict(self, ll, fields=None):
        props = ll.get_loadbalancer_listener_properties()
        res = {'id': ll.uuid,
               'tenant_id': ll.parent_uuid.replace('-', ''),
               'name': ll.display_name,
               'description': self._get_object_description(ll),
               'protocol': props.protocol,
               'protocol_port': props.protocol_port,
               'admin_state_up': props.admin_state,
               'loadbalancers' : self._get_loadbalancers(ll)}
        if res['loadbalancers']:
            res['loadbalancer_id'] = res['loadbalancers'][0]['id']

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.loadbalancer_listener_read(id=id)

    def resource_list(self, tenant_id=None):
        if tenant_id:
            parent_id = str(uuid.UUID(tenant_id))
        else:
            parent_id = None
        return self._api.loadbalancer_listeners_list(parent_id=parent_id)

    def resource_update(self, obj):
        return self._api.loadbalancer_listener_update(obj)

    def resource_delete(self, id):
        return self._api.loadbalancer_listener_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

    def get_exception_inuse(self, id=None):
        return EntityInUse(name=self.neutron_name, id=id)

    @property
    def neutron_name(self):
        return "listener"

    @property
    def resource_name_plural(self):
        return "loadbalancer-listeners"

    def create(self, context, listener):
        l = listener['listener']
        tenant_id = self._get_tenant_id_for_create(context, l)
        project = self._project_read(project_id=tenant_id)

        if l['loadbalancer_id']:
            try:
                lb = self._api.loadbalancer_read(id=l['loadbalancer_id'])
            except NoIdError:
                raise loadbalancerv2.EntityNotFound(name='Loadbalancer',
                                                    id=v['loadbalancer_id'])
            project_id = lb.parent_uuid
            if str(uuid.UUID(tenant_id)) != project_id:
                raise NotAuthorized()
        else:
            lb = None

        obj_uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('loadbalancer-listener',
                                       project, l['name'], obj_uuid)
        id_perms = IdPermsType(enable=True, description=l['description'])
        ll = LoadbalancerListener(name, project, id_perms=id_perms,
                                  display_name=l['name'])
        ll.uuid = obj_uuid

        if lb:
            ll.set_loadbalancer(lb)

        props = self.make_properties(l)
        ll.set_loadbalancer_listener_properties(props)

        self._api.loadbalancer_listener_create(ll)
        return self.make_dict(ll)

    def delete_listener(self, context, id):
        try:
            ll = self._api.loadbalancer_listener_read(id=id)
        except NoIdError:
            loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

        super(ListenerManager, self).delete(context, id)

    def _update_listener_properties(self, props, id, ll):
        """
        Update listener properties and return True if the have been
        modified
        """
        # according to the spec:
        # port and protocol are immutable
        immutable = ['protocol', 'protocol_port']
        for field in immutable:
            if field not in ll:
                continue
            if getattr(props, field) != ll[field]:
                msg = 'Attribute %s in listener %s is immutable' % (field, id)
                raise BadRequest(resource='listener', msg=msg)

        # update
        change = self.update_properties_subr(props, ll)
        return change


    def update_properties(self, ll_db, id, ll):
        props = ll_db.get_loadbalancer_listener_properties()
        if self._update_listener_properties(props, id, ll):
            ll_db.set_loadbalancer_listener_properties(props)
            return True
        return False
