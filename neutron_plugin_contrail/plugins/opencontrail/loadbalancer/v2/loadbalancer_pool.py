#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid

try:
    from neutron.extensions import loadbalancer
except ImportError:
    from neutron_lbaas.extensions import loadbalancer

from neutron.api.v2 import attributes as attr
from neutron.plugins.common import constants
from neutron.services import provider_configuration as pconf

from neutron.openstack.common import uuidutils
from vnc_api.vnc_api import *

from resource_manager import ResourceManager
from resource_manager import LoadbalancerMethodInvalid

import uuid

class LoadbalancerPoolManager(ResourceManager):

    _loadbalancer_pool_type_mapping = {
        'admin_state': 'admin_state_up',
        'protocol': 'protocol',
        'loadbalancer_method': 'lb_method',
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
        return props

    def _get_listeners(self, pool):
        ll_list = []
        ll_back_refs = pool.get_loadbalancer_listener_back_refs()
        if ll_back_refs:
            for ll_back_ref in ll_back_refs:
                ll_list.append({'id': ll_back_ref['uuid']})
        return ll_list

    def create_update_custom_attributes(self, custom_attributes, kvps):
        kvp_array = []
        for custom_attribute in custom_attributes or []:
            for key,value in custom_attribute.iteritems():
                kvp = KeyValuePair(key, value)
                kvp_array.append(kvp)

        kvps.set_key_value_pair(kvp_array)
        return True

    def make_dict(self, pool, fields=None):
        res = {
            'id': pool.uuid,
            'tenant_id': pool.parent_uuid.replace('-', ''),
            'name': pool.display_name,
            'description': self._get_object_description(pool),
            'status': self._get_object_status(pool),
            'listeners': self._get_listeners(pool),
        }

        props = pool.get_loadbalancer_pool_properties()
        for key, mapping in self._loadbalancer_pool_type_mapping.iteritems():
            value = getattr(props, key, None)
            if value is not None:
                res[mapping] = value

        custom_attributes = []
        kvps = pool.get_loadbalancer_pool_custom_attributes()
        if kvps:
            custom_attributes = [{kvp.get_key(): kvp.get_value()} for kvp in kvps.get_key_value_pair() or []]

        res['custom_attributes'] = [custom_attributes]
        res['provider'] = pool.get_loadbalancer_pool_provider()

        # members
        res['members'] = []
        members = pool.get_loadbalancer_members()
        if members is not None:
            res['members'] = [member['uuid'] for member in members]

        # health_monitors
        res['health_monitors'] = []
        hm_refs = pool.get_loadbalancer_healthmonitor_refs()
        if hm_refs is not None:
            res['health_monitors'] = [hm['uuid'] for hm in hm_refs]

        # TODO: health_monitor_status
        res['health_monitors_status'] = []

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
        return loadbalancer.PoolNotFound(pool_id=id)

    def get_exception_inuse(self, id=None):
        return loadbalancer.PoolInUse(pool_id=id)

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
        try:
            sas_fq_name = ["default-global-system-config"]
            sas_fq_name.append(p['provider'])
            sas_obj = self._api.service_appliance_set_read(fq_name=sas_fq_name)
        except NoIdError:
            raise pconf.ServiceProviderNotFound(
                provider=p['provider'], service_type=constants.LOADBALANCER)

        tenant_id = self._get_tenant_id_for_create(context, p)
        project = self._project_read(project_id=tenant_id)

        if p['listener_id']:
            try:
                ll = self._api.loadbalancer_listener_read(id=p['listener_id'])
            except NoIdError:
                raise loadbalancer.EntityNotFound(id=p['listener_id'])
            project_id = ll.parent_uuid
            if str(uuid.UUID(tenant_id)) != project_id:
                raise n_exc.NotAuthorized()
        else:
            ll = None

        pool_uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('loadbalancer-pool', project,
                                       p['name'], pool_uuid)
        props = self.make_properties(p)
        id_perms = IdPermsType(enable=True,
                               description=p['description'])
        pool = LoadbalancerPool(name, project,
                                loadbalancer_pool_properties=props,
                                loadbalancer_pool_provider=p['provider'],
                                id_perms=id_perms, display_name=p['name'])
        pool.uuid = pool_uuid

        pool.set_service_appliance_set(sas_obj)

         # Custom attributes
        if p['custom_attributes'] != attr.ATTR_NOT_SPECIFIED:
            custom_attributes = KeyValuePairs()
            self.create_update_custom_attributes(p['custom_attributes'], custom_attributes)
            pool.set_loadbalancer_pool_custom_attributes(custom_attributes)

        self._api.loadbalancer_pool_create(pool)

        if ll:
            ll.set_loadbalancer_pool(pool)
            self._api.loadbalancer_listener_update(ll)

        return self.make_dict(pool)

    def update_properties(self, pool_db, id, p):
        props = pool_db.get_loadbalancer_pool_properties()
        change = False
        if self.update_properties_subr(props, p):
            pool_db.set_loadbalancer_pool_properties(props)
            change = True

        if 'custom_attributes' in p:
            custom_attributes = pool_db.get_loadbalancer_pool_custom_attributes()
            # Make sure to initialize custom_attributes
            if not custom_attributes:
                custom_attributes = KeyValuePairs()

            if self.create_update_custom_attributes(p['custom_attributes'], custom_attributes):
                pool_db.set_loadbalancer_pool_custom_attributes(custom_attributes)
                change = True

        return change
