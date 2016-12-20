#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid

from neutron_lbaas.extensions import loadbalancerv2
try:
    from neutron.api.v2.attributes import ATTR_NOT_SPECIFIED
except:
    from neutron_lib.constants import ATTR_NOT_SPECIFIED

try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils
from vnc_api.vnc_api import *

from .. resource_manager import ResourceManager, EntityInUse
from .. resource_manager import LoadbalancerMethodInvalid

import uuid

class LoadbalancerPoolManager(ResourceManager):

    _loadbalancer_pool_type_mapping = {
        'admin_state': 'admin_state_up',
        'protocol': 'protocol',
        'loadbalancer_method': 'lb_algorithm',
        'subnet_id': 'subnet_id'
    }

    @property
    def property_type_mapping(self):
        return self._loadbalancer_pool_type_mapping

    def make_properties(self, pool):
        props = LoadbalancerPoolType()
        for key, mapping in self._loadbalancer_pool_type_mapping.iteritems():
            if mapping in pool:
                setattr(props, key, pool[mapping])
        sp = pool['session_persistence']
        if sp is not None:
            if 'type' in sp:
                props.session_persistence = sp['type']
            if 'cookie_name' in sp:
                props.persistence_cookie_name = sp['cookie_name']
        return props

    def create_update_custom_attributes(self, custom_attributes, kvps):
        kvp_array = []
        for custom_attribute in custom_attributes or []:
            for key,value in custom_attribute.iteritems():
                kvp = KeyValuePair(key, value)
                kvp_array.append(kvp)

        kvps.set_key_value_pair(kvp_array)
        return True

    def _get_listeners(self, pool):
        ll_list = []
        ll = {}
        ll_back_refs = pool.get_loadbalancer_listener_refs()
        if ll_back_refs is None:
            return None
        ll['id'] = ll_back_refs[0]['uuid']
        ll_list.append(ll)
        return ll_list

    def make_dict(self, pool, fields=None):
        res = {
            'id': pool.uuid,
            'tenant_id': pool.parent_uuid.replace('-', ''),
            'name': pool.display_name,
            'description': self._get_object_description(pool),
            'status': self._get_object_status(pool),
            'listeners': self._get_listeners(pool),
            'session_persistence': None,
        }
        if res['listeners']:
            res['listener_id'] = res['listeners'][0]['id']

        props = pool.get_loadbalancer_pool_properties()
        for key, mapping in self._loadbalancer_pool_type_mapping.iteritems():
            value = getattr(props, key, None)
            if value is not None:
                res[mapping] = value

        custom_attributes = []
        kvps = pool.get_loadbalancer_pool_custom_attributes()
        if kvps:
            custom_attributes = [{kvp.get_key(): kvp.get_value()} \
                                 for kvp in kvps.get_key_value_pair() or []]
        res['custom_attributes'] = [custom_attributes]

        if props.session_persistence:
            sp = {'type': props.session_persistence}
            if props.session_persistence == 'APP_COOKIE':
                sp['cookie_name'] = props.persistence_cookie_name
            res['session_persistence'] = sp

        # members
        res['members'] = []
        members = pool.get_loadbalancer_members()
        if members is not None:
            res['members'] = [{'id': member['uuid']} for member in members]

        # health_monitor
        hm_refs = pool.get_loadbalancer_healthmonitor_refs()
        if hm_refs is not None:
            res['healthmonitor_id'] = hm_refs[0]['uuid']

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.loadbalancer_pool_read(id=id)

    def resource_list(self, tenant_id=None):
        if tenant_id:
            parent_id = str(uuid.UUID(tenant_id))
        else:
            parent_id = None
        return self._api.loadbalancer_pools_list(parent_id=parent_id)

    def resource_update(self, obj):
        try:
            return self._api.loadbalancer_pool_update(obj)
        except HttpError as e:
            if 'LoadbalancerMethodType' in e.content:
                pool_props = obj.get_loadbalancer_pool_properties()
                lb_method = pool_props.get_loadbalancer_method()
                raise LoadbalancerMethodInvalid(lb_method=lb_method,
                                                pool_id=obj.uuid)

    def resource_delete(self, id):
        return self._api.loadbalancer_pool_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

    def get_exception_inuse(self, id=None):
        return EntityInUse(name=self.neutron_name, id=id)

    @property
    def neutron_name(self):
        return "pool"

    @property
    def resource_name_plural(self):
        return "loadbalancer-pools"

    def create(self, context, pool):
        """
        Create a loadbalancer_pool object.
        """
        p = pool['pool']
        tenant_id = self._get_tenant_id_for_create(context, p)
        project = self._project_read(project_id=tenant_id)

        if p['listener_id']:
            try:
                ll = self._api.loadbalancer_listener_read(id=p['listener_id'])
            except NoIdError:
                raise loadbalancerv2.EntityNotFound(name='Listener',
                                                    id=p['listener_id'])
            project_id = ll.parent_uuid
            if str(uuid.UUID(tenant_id)) != project_id:
                raise exc.NotAuthorized()
        else:
            ll = None

        pool_uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('loadbalancer-pool', project,
                                       p['name'], pool_uuid)
        props = self.make_properties(p)
        id_perms = IdPermsType(enable=True,
                               description=p['description'])
        pool = LoadbalancerPool(name, project, uuid=pool_uuid,
                                loadbalancer_pool_properties=props,
                                id_perms=id_perms, display_name=p['name'])

        if ll:
            pool_exists = ll.get_loadbalancer_pool_back_refs()
            if pool_exists is not None:
                raise loadbalancerv2.OnePoolPerListener(
                                     listener_id=p['listener_id'],
                                     pool_id=pool_exists[0]['uuid'])
            pool.set_loadbalancer_listener(ll)

        # Custom attributes
        if p['custom_attributes'] != ATTR_NOT_SPECIFIED:
            custom_attributes = KeyValuePairs()
            self.create_update_custom_attributes(p['custom_attributes'],
                                                 custom_attributes)
            pool.set_loadbalancer_pool_custom_attributes(custom_attributes)

        self._api.loadbalancer_pool_create(pool)
        return self.make_dict(pool)

    def _update_pool_properties(self, props, pool):
        change = self.update_properties_subr(props, pool)
        if 'session_persistence' in pool:
            sp = pool['session_persistence']
            new_type = sp.get('type', None)
            if props.session_persistence != new_type:
                props.session_persistence = new_type
                change = True
            new_cookie_name = sp.get('cookie_name', None)
            if props.persistence_cookie_name != new_cookie_name and \
                    props.session_persistence == 'APP_COOKIE':
                props.persistence_cookie_name = new_cookie_name
                change = True
        return change

    def update_properties(self, pool_db, id, p):
        props = pool_db.get_loadbalancer_pool_properties()
        change = False
        if self._update_pool_properties(props, p):
            pool_db.set_loadbalancer_pool_properties(props)
            change = True

        if 'custom_attributes' in p:
            custom_attributes = pool_db.get_loadbalancer_pool_custom_attributes()
            # Make sure to initialize custom_attributes
            if not custom_attributes:
                custom_attributes = KeyValuePairs()

            if self.create_update_custom_attributes(p['custom_attributes'],
                                                    custom_attributes):
                pool_db.set_loadbalancer_pool_custom_attributes(custom_attributes)
                change = True

        return change
