#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid

from neutron_lbaas.extensions import loadbalancerv2
try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils

from vnc_api.vnc_api import IdPermsType
from vnc_api.vnc_api import LoadbalancerHealthmonitor
from vnc_api.vnc_api import LoadbalancerHealthmonitorType

from .. resource_manager import ResourceManager, EntityInUse


class LoadbalancerHealthmonitorManager(ResourceManager):
    _loadbalancer_health_type_mapping = {
        'admin_state': 'admin_state_up',
        'monitor_type': 'type',
        'delay': 'delay',
        'timeout': 'timeout',
        'max_retries': 'max_retries',
        'http_method': 'http_method',
        'url_path': 'url_path',
        'expected_codes': 'expected_codes'
    }

    @property
    def property_type_mapping(self):
        return self._loadbalancer_health_type_mapping

    def make_properties(self, healthmonitor):
        props = LoadbalancerHealthmonitorType()
        for key, mapping in self._loadbalancer_health_type_mapping.iteritems():
            if mapping in healthmonitor:
                setattr(props, key, healthmonitor[mapping])
        return props

    def make_dict(self, healthmonitor, fields=None):
        res = {'id': healthmonitor.uuid,
               'tenant_id': healthmonitor.parent_uuid.replace('-', ''),
               'status': self._get_object_status(healthmonitor)}

        props = healthmonitor.get_loadbalancer_healthmonitor_properties()
        monitor_type = getattr(props, 'monitor_type')
        for key, mapping in self._loadbalancer_health_type_mapping.iteritems():
            value = getattr(props, key)
            if value is not None:
                if monitor_type not in ('HTTP', 'HTTPS'):
                    if mapping in ('http_method', 'url_path', 'expected_codes'):
                        continue
                res[mapping] = value

        pool_ids = []
        pool_back_refs = healthmonitor.get_loadbalancer_pool_back_refs()
        for pool_back_ref in pool_back_refs or []:
            pool_id = {}
            pool_id['pool_id'] = pool_back_ref['uuid']
            pool_ids.append(pool_id)
        res['pools'] = pool_ids

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.loadbalancer_healthmonitor_read(id=id)

    def resource_list(self, tenant_id=None):
        if tenant_id:
            parent_id = str(uuid.UUID(tenant_id))
        else:
            parent_id = None
        return self._api.loadbalancer_healthmonitors_list(parent_id=parent_id)

    def resource_update(self, obj):
        return self._api.loadbalancer_healthmonitor_update(obj)

    def resource_delete(self, id):
        return self._api.loadbalancer_healthmonitor_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancerv2.EntityNotFound(name=self.neutron_name, id=id)

    def get_exception_inuse(self, id=None):
        return EntityInUse(name=self.neutron_name, id=id)

    @property
    def neutron_name(self):
        return "healthmonitor"

    @property
    def resource_name_plural(self):
        return "loadbalancer-healthmonitors"

    def create(self, context, healthmonitor):
        """
        Create a loadbalancer_healtmonitor object.
        """
        m = healthmonitor['healthmonitor']
        tenant_id = self._get_tenant_id_for_create(context, m)
        project = self._project_read(project_id=tenant_id)

        uuid = uuidutils.generate_uuid()
        props = self.make_properties(m)
        id_perms = IdPermsType(enable=True)
        monitor_db = LoadbalancerHealthmonitor(
            uuid, project, loadbalancer_healthmonitor_properties=props,
            id_perms=id_perms)
        monitor_db.uuid = uuid

        try:
            pool = self._api.loadbalancer_pool_read(id=m['pool_id'])
        except NoIdError:
            raise loadbalancerv2.EntityNotFound(name='Pool', id=m['pool_id'])
        exist_hm_refs = pool.get_loadbalancer_healthmonitor_refs()
        if exist_hm_refs is not None:
            raise loadbalancerv2.OneHealthMonitorPerPool(pool_id=m['pool_id'],
                                               hm_id=exist_hm_refs[0]['uuid'])
        self._api.loadbalancer_healthmonitor_create(monitor_db)
        self._api.ref_update('loadbalancer-pool', m['pool_id'],
            'loadbalancer-health-monitor', uuid, None, 'ADD')
        return self.make_dict(monitor_db)

    def delete(self, context, id):
        hm_obj = self._api.loadbalancer_healthmonitor_read(id=id)
        for pool_back_refs in hm_obj.get_loadbalancer_pool_back_refs() or []:
            self._api.ref_update('loadbalancer-pool', pool_back_refs['uuid'],
                'loadbalancer-health-monitor', id, None, 'DELETE')
        super(LoadbalancerHealthmonitorManager, self).delete(context, id)

    def update_properties(self, monitor_db, id, m):
        props = monitor_db.get_loadbalancer_healthmonitor_properties()
        if self.update_properties_subr(props, m):
            monitor_db.set_loadbalancer_healthmonitor_properties(props)
            return True
        return False
