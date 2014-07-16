#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.plugin \
    import LoadBalancerPlugin
from vnc_api.vnc_api import IdPermsType
from vnc_api.vnc_api import LoadbalancerHealthmonitor
from vnc_api.vnc_api import LoadbalancerHealthmonitorType
from vnc_api.vnc_api import LoadbalancerMember, LoadbalancerMemberType
from vnc_api.vnc_api import LoadbalancerPool, LoadbalancerPoolType
from vnc_api.vnc_api import Project
from vnc_api.vnc_api import VirtualIp, VirtualIpType
from vnc_api.vnc_api import VirtualNetwork
from vnc_api.vnc_api import VncApi
from webob import exc
import copy
import mock
import neutron.services.loadbalancer.drivers.abstract_driver as abstract_driver

_PLUGIN = 'neutron_plugin_contrail.plugins.opencontrail.' \
    'loadbalancer.plugin.LoadBalancerPlugin'

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class OpencontrailLoadbalancerTest(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        super(OpencontrailLoadbalancerTest, self).setUp()
        self._setUpExtension(
            _PLUGIN,
            constants.LOADBALANCER, loadbalancer.RESOURCE_ATTRIBUTE_MAP,
            loadbalancer.Loadbalancer, 'lb', use_quota=True)

        self._plugin_patcher.stop()

        plugin_path = '.'.join(_PLUGIN.split('.')[:-2])
        db_class_name = plugin_path + '.loadbalancer_db'
        self._vnc_patcher = mock.patch('%s.VncApi' % db_class_name,
                                       autospec=True)
        self._vnc_patcher.start()

        plugin_class_name = plugin_path + '.plugin'
        self._driver_patcher = mock.patch(
            '%s.service_base' % plugin_class_name, autospec=True)
        self._driver = mock.Mock(abstract_driver.LoadBalancerAbstractDriver)
        service_base = self._driver_patcher.start()
        service_base.load_drivers.return_value = ({
            'lbaas': self._driver
        }, 'lbaas')

        self.loadbalancer = LoadBalancerPlugin()
        self.loadbalancer._get_driver_for_pool = self._driver
        self.api_server = self.loadbalancer._api

        self._project = None

    def tearDown(self):
        self._vnc_patcher.stop()
        self._driver_patcher.stop()
        super(OpencontrailLoadbalancerTest, self).tearDown()

    def _project_read(self, *args, **kwargs):
        """ Return a mock project with the expected values """
        project = Project()
        project.uuid = kwargs['id']
        project.fq_name = ['default-domain', 'test']
        self._project = project
        return project

    def _loadbalancer_pool_read(self, *args, **kwargs):
        pool = LoadbalancerPool()
        pool.uuid = kwargs['id']
        pool.parent_uuid = self._project.uuid
        return pool

    def test_vip_create(self):
        def create_vip(*args, **kwargs):
            return self.loadbalancer.create_vip(*args, **kwargs)

        self.plugin.return_value.create_vip.side_effect = create_vip

        self._port_id = None

        def api_virtual_machine_interface_create(*args, **kwargs):
            vmi = args[0]
            vmi.uuid = _uuid()
            self._port_id = vmi.uuid
            return vmi.uuid

        def api_virtual_ip_create(*args, **kwargs):
            vip = args[0]
            vip.parent_uuid = self._project.uuid
            return vip.uuid

        instance = self.api_server
        instance.fq_name_to_id.return_value = None
        instance.project_read.side_effect = self._project_read
        instance.loadbalancer_pool_read.side_effect = \
            self._loadbalancer_pool_read
        instance.kv_retrieve.return_value = '%s %s' % (_uuid(), _uuid())
        vnet = VirtualNetwork('default')
        instance.virtual_network_read.return_value = vnet
        instance.virtual_machine_interface_create.side_effect = \
            api_virtual_machine_interface_create
        instance.virtual_ip_create.side_effect = api_virtual_ip_create

        data = {'vip': {'name': 'vip1',
                        'description': 'descr_vip1',
                        'subnet_id': _uuid(),
                        'address': '127.0.0.1',
                        'protocol_port': 80,
                        'protocol': 'HTTP',
                        'pool_id': _uuid(),
                        'session_persistence': {'type': 'HTTP_COOKIE'},
                        'connection_limit': 100,
                        'admin_state_up': True,
                        'tenant_id': _uuid()}}

        res = self.api.post(_get_path('lb/vips', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)
        expected = copy.copy(data['vip'])
        expected.update({'status': "ACTIVE",
                         'port_id': self._port_id,
                         'id': res['vip']['id']
                         })
        self.assertEqual(expected, res['vip'])

    def _virtual_ip_properties_build(self):
        props = VirtualIpType()
        props.address = '127.0.0.1'
        props.protocol = 'HTTP'
        props.protocol_port = 80
        props.connection_limit = 100
        props.subnet_id = _uuid()
        props.admin_state = True
        return props

    def _loadbalancer_pool_properties_build(self):
        props = LoadbalancerPoolType()
        props.protocol = 'HTTP'
        props.loadbalancer_method = 'ROUND_ROBIN'
        props.subnet_id = _uuid()
        props.admin_state = True
        return props

    def _loadbalancer_member_properties_build(self):
        props = LoadbalancerMemberType()
        props.address = '127.0.0.1'
        props.protocol_port = 80
        props.weight = 1
        props.admin_state = True
        return props

    def _loadbalancer_healthmonitor_properties_build(self):
        props = LoadbalancerHealthmonitorType()
        props.type = 'HTTP'
        props.delay = 2
        props.timeout = 1
        props.max_retries = 3
        props.http_method = 'GET'
        props.url_path = '/path'
        props.expected_codes = '200-300'
        props.admin_state = True
        return props

    def _create_pool(self, pool_id, tenant_id=None):
        if tenant_id is None:
            tenant_id = _uuid()
        id_perms = IdPermsType(uuid=pool_id, enable=True)
        props = self._loadbalancer_pool_properties_build()
        pool = LoadbalancerPool(loadbalancer_pool_properties=props,
                                id_perms=id_perms,
                                display_name='pool1')
        pool.parent_uuid = tenant_id
        pool.uuid = pool_id
        return pool

    def _create_member(self, member_id, pool_id):
        id_perms = IdPermsType(uuid=member_id, enable=True)
        props = self._loadbalancer_member_properties_build()
        member = LoadbalancerMember(loadbalancer_member_properties=props,
                                    id_perms=id_perms)
        member.uuid = member_id
        member.parent_uuid = pool_id
        return member

    def _create_monitor(self, health_monitor_id, tenant_id):
        id_perms = IdPermsType(uuid=health_monitor_id, enable=True)
        props = self._loadbalancer_healthmonitor_properties_build()
        monitor = LoadbalancerHealthmonitor(
            health_monitor_id,
            loadbalancer_healthmonitor_properties=props,
            id_perms=id_perms)
        monitor.parent_uuid = tenant_id
        monitor.uuid = health_monitor_id
        return monitor

    def test_vip_list(self):
        def get_vips(*args, **kwargs):
            return self.loadbalancer.get_vips(*args, **kwargs)

        self.plugin.return_value.get_vips.side_effect = get_vips

        virtual_ip_list = [
            {'fq_name': ['default-domain', 'test', 'vip1'], 'uuid': _uuid()},
            {'fq_name': ['default-domain', 'test', 'vip2'], 'uuid': _uuid()}
            ]
        instance = self.api_server
        instance.virtual_ips_list.return_value = {
            'virtual-ips': virtual_ip_list
        }

        def virtual_ip_read(*args, **kwargs):
            props = self._virtual_ip_properties_build()
            vip = VirtualIp(virtual_ip_properties=props)
            vip.uuid = kwargs['id']
            vip.parent_uuid = _uuid()
            return vip

        instance.virtual_ip_read.side_effect = virtual_ip_read

        res = self.api.get(_get_path('lb/vips', fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPOk.code)

        res = self.deserialize(res)
        self.assertIn('vips', res)
        self.assertEqual(2, len(res['vips']))

    def test_vip_list_w_filter(self):
        def get_vips(*args, **kwargs):
            return self.loadbalancer.get_vips(*args, **kwargs)

        self.plugin.return_value.get_vips.side_effect = get_vips

        vip1_id = _uuid()
        vip2_id = _uuid()
        virtual_ip_list = [
            {'fq_name': ['default-domain', 'test', 'vip1'], 'uuid': vip1_id},
            {'fq_name': ['default-domain', 'test', 'vip2'], 'uuid': vip2_id}
            ]
        instance = self.api_server
        instance.virtual_ips_list.return_value = {
            'virtual-ips': virtual_ip_list
        }

        def virtual_ip_read(*args, **kwargs):
            name = None
            props = VirtualIpType()
            props.address = '127.0.0.1'
            if kwargs['id'] == vip1_id:
                name = 'vip1'
                props.protocol = 'HTTP'
            elif kwargs['id'] == vip2_id:
                name = 'vip2'
                props.protocol = 'HTTPS'
            props.protocol_port = 80
            props.connection_limit = 100
            props.subnet_id = _uuid()
            props.admin_state = True
            vip = VirtualIp(virtual_ip_properties=props, display_name=name)
            vip.uuid = kwargs['id']
            vip.parent_uuid = _uuid()
            return vip

        instance.virtual_ip_read.side_effect = virtual_ip_read

        res = self.api.get(_get_path('lb/vips', fmt=self.fmt),
                           {'protocol': ['HTTP']})
        self.assertEqual(res.status_int, exc.HTTPOk.code)

        res = self.deserialize(res)
        self.assertIn('vips', res)
        self.assertEqual(1, len(res['vips']))
        self.assertEqual('vip1', res['vips'][0]['name'])

    def test_vip_update(self):
        def update_vip(*args, **kwargs):
            return self.loadbalancer.update_vip(*args, **kwargs)

        self.plugin.return_value.update_vip.side_effect = update_vip

        vip_id = _uuid()

        id_perms = IdPermsType(uuid=vip_id, enable=True)
        props = self._virtual_ip_properties_build()
        vip = VirtualIp(virtual_ip_properties=props, id_perms=id_perms,
                        display_name='vip1')
        vip.parent_uuid = _uuid()
        vip.uuid = vip_id

        instance = self.api_server
        instance.virtual_ip_read.return_value = vip

        update_data = {'vip': {'admin_state_up': False}}

        res = self.api.put(_get_path('lb/vips', id=vip_id, fmt=self.fmt),
                           self.serialize(update_data))

        instance.virtual_ip_update.assert_called_with(mock.ANY)

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)

        return_value = {'name': 'vip1',
                        'admin_state_up': False,
                        'tenant_id': vip.parent_uuid,
                        'status': "ACTIVE",
                        'id': vip_id}
        self.assertDictContainsSubset(return_value, res['vip'])

    def test_vip_get(self):
        def get_vip(*args, **kwargs):
            return self.loadbalancer.get_vip(*args, **kwargs)

        self.plugin.return_value.get_vip.side_effect = get_vip

        vip_id = _uuid()

        id_perms = IdPermsType(uuid=vip_id, enable=True)
        props = self._virtual_ip_properties_build()
        vip = VirtualIp(virtual_ip_properties=props, id_perms=id_perms,
                        display_name='vip1')
        vip.parent_uuid = _uuid()
        vip.uuid = vip_id

        instance = self.api_server
        instance.virtual_ip_read.return_value = vip

        return_value = {'name': 'vip1',
                        'admin_state_up': True,
                        'tenant_id': vip.parent_uuid,
                        'status': "ACTIVE",
                        'id': vip_id}

        res = self.api.get(_get_path('lb/vips', id=vip_id, fmt=self.fmt))

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('vip', res)
        self.assertDictContainsSubset(return_value, res['vip'])

    def test_vip_delete(self):
        def delete_vip(*args, **kwargs):
            return self.loadbalancer.delete_vip(*args, **kwargs)

        self.plugin.return_value.delete_vip.side_effect = delete_vip

        vip_id = _uuid()
        res = self.api.delete(_get_path('lb/vips', id=vip_id, fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

        instance = self.api_server
        instance.virtual_ip_delete.assert_called_with(id=vip_id)

    def test_pool_create(self):
        def create_pool(*args, **kwargs):
            return self.loadbalancer.create_pool(*args, **kwargs)

        def api_loadbalancer_pool_create(*args, **kwargs):
            pool = args[0]
            pool.parent_uuid = self._project.uuid
            return pool.uuid

        def healthmonitor_read(*args, **kwargs):
            hm = LoadbalancerHealthmonitor('hm1', self._project)
            hm.uuid = kwargs['id']
            return hm

        self.plugin.return_value.create_pool.side_effect = create_pool

        hm_id = _uuid()
        data = {'pool': {'name': 'pool1',
                         'description': 'descr_pool1',
                         'subnet_id': _uuid(),
                         'protocol': 'HTTP',
                         'lb_method': 'ROUND_ROBIN',
                         'health_monitors': [hm_id],
                         'admin_state_up': True,
                         'tenant_id': _uuid()}}

        instance = self.api_server
        instance.fq_name_to_id.return_value = None
        instance.project_read.side_effect = self._project_read

        instance.loadbalancer_pool_create.side_effect = \
            api_loadbalancer_pool_create

        instance.loadbalancer_healthmonitor_read.side_effect = \
            healthmonitor_read
        res = self.api.post(_get_path('lb/pools', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)

        return_value = copy.copy(data['pool'])
        return_value['provider'] = 'lbaas'
        return_value.update({'status': "ACTIVE", 'id': res['pool']['id']})
        self.assertEqual(return_value, res['pool'])

    def test_pool_list(self):
        def get_pools(*args, **kwargs):
            return self.loadbalancer.get_pools(*args, **kwargs)

        self.plugin.return_value.get_pools.side_effect = get_pools

        loadbalancer_pool_list = [
            {'fq_name': ['default-domain', 'test', 'pool1'], 'uuid': _uuid()},
            {'fq_name': ['default-domain', 'test', 'pool2'], 'uuid': _uuid()},
        ]
        instance = self.api_server
        instance.loadbalancer_pools_list.return_value = {
            'loadbalancer-pools': loadbalancer_pool_list
        }

        def loadbalancer_pool_read(*args, **kwargs):
            props = self._loadbalancer_pool_properties_build()
            pool = LoadbalancerPool(loadbalancer_pool_properties=props)
            pool.uuid = kwargs['id']
            pool.parent_uuid = _uuid()
            return pool

        instance.loadbalancer_pool_read.side_effect = loadbalancer_pool_read

        res = self.api.get(_get_path('lb/pools', fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPOk.code)

        res = self.deserialize(res)
        self.assertIn('pools', res)
        self.assertEqual(2, len(res['pools']))

    def test_pool_update(self):
        def update_pool(*args, **kwargs):
            return self.loadbalancer.update_pool(*args, **kwargs)

        self.plugin.return_value.update_pool.side_effect = update_pool

        pool_id = _uuid()
        pool = self._create_pool(pool_id)

        instance = self.api_server
        instance.loadbalancer_pool_read.return_value = pool

        update_data = {'pool': {'admin_state_up': False}}

        res = self.api.put(_get_path('lb/pools', id=pool_id, fmt=self.fmt),
                           self.serialize(update_data))

        instance.loadbalancer_pool_update.assert_called_with(mock.ANY)

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)

        return_value = {'name': 'pool1',
                        'admin_state_up': False,
                        'tenant_id': pool.parent_uuid,
                        'status': "ACTIVE",
                        'id': pool_id}
        self.assertDictContainsSubset(return_value, res['pool'])

    def test_pool_get(self):
        def get_pool(*args, **kwargs):
            return self.loadbalancer.get_pool(*args, **kwargs)

        self.plugin.return_value.get_pool.side_effect = get_pool

        pool_id = _uuid()
        pool = self._create_pool(pool_id)

        instance = self.api_server
        instance.loadbalancer_pool_read.return_value = pool

        res = self.api.get(_get_path('lb/pools', id=pool_id, fmt=self.fmt))

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('pool', res)
        return_value = {'name': 'pool1',
                        'admin_state_up': True,
                        'tenant_id': pool.parent_uuid,
                        'status': "ACTIVE",
                        'id': pool_id}
        self.assertDictContainsSubset(return_value, res['pool'])

    def test_pool_delete(self):
        def delete_pool(*args, **kwargs):
            return self.loadbalancer.delete_pool(*args, **kwargs)

        self.plugin.return_value.delete_pool.side_effect = delete_pool

        pool_id = _uuid()
        res = self.api.delete(_get_path('lb/pools', id=pool_id, fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

        instance = self.api_server
        instance.loadbalancer_pool_delete.assert_called_with(id=pool_id)

    def test_member_create(self):
        def create_member(*args, **kwargs):
            return self.loadbalancer.create_member(*args, **kwargs)

        self.plugin.return_value.create_member.side_effect = create_member

        pool_id = _uuid()
        pool = self._create_pool(pool_id)

        def api_loadbalancer_member_create(*args, **kwargs):
            mbr = args[0]
            mbr.parent_uuid = pool_id
            return mbr.uuid

        instance = self.api_server
        instance.fq_name_to_id.return_value = None
        instance.loadbalancer_pool_read.return_value = pool
        instance.loadbalancer_member_create.side_effect = \
            api_loadbalancer_member_create

        data = {'member': {'pool_id': pool_id,
                           'address': '127.0.0.1',
                           'protocol_port': 80,
                           'weight': 1,
                           'admin_state_up': True,
                           'tenant_id': pool.parent_uuid}}

        res = self.api.post(_get_path('lb/members', fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('member', res)

        return_value = copy.copy(data['member'])
        return_value.update({'status': "ACTIVE", 'id': res['member']['id']})

        self.assertEqual(return_value, res['member'])

    def test_member_list(self):
        def get_members(*args, **kwargs):
            return self.loadbalancer.get_members(*args, **kwargs)

        self.plugin.return_value.get_members.side_effect = get_members

        uuid1 = _uuid()
        uuid2 = _uuid()
        loadbalancer_member_list = [
            {'fq_name': ['default-domain', 'test', uuid1], 'uuid': uuid1},
            {'fq_name': ['default-domain', 'test', uuid2], 'uuid': uuid2},
        ]

        instance = self.api_server
        instance.loadbalancer_members_list.return_value = {
            'loadbalancer-members': loadbalancer_member_list
        }

        pool_id = _uuid()
        pool = self._create_pool(pool_id)

        instance.loadbalancer_pool_read.return_value = pool

        def loadbalancer_member_read(*args, **kwargs):
            member = self._create_member(kwargs['id'], pool_id)
            return member

        instance.loadbalancer_member_read.side_effect = \
            loadbalancer_member_read

        res = self.api.get(_get_path('lb/members', fmt=self.fmt))

        self.assertEqual(res.status_int, exc.HTTPOk.code)

        res = self.deserialize(res)
        self.assertIn('members', res)
        self.assertEqual(2, len(res['members']))

    def test_member_update(self):
        def update_member(*args, **kwargs):
            return self.loadbalancer.update_member(*args, **kwargs)

        self.plugin.return_value.update_member.side_effect = update_member

        member_id = _uuid()
        pool_id = _uuid()

        pool = self._create_pool(pool_id)
        member = self._create_member(member_id, pool_id)

        instance = self.api_server
        instance.loadbalancer_pool_read.return_value = pool
        instance.loadbalancer_member_read.return_value = member

        update_data = {'member': {'admin_state_up': False}}

        res = self.api.put(_get_path('lb/members', id=member_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.loadbalancer_member_update.assert_called_with(mock.ANY)

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('member', res)
        return_value = {'admin_state_up': False,
                        'tenant_id': pool.parent_uuid,
                        'status': "ACTIVE",
                        'id': member_id}

        self.assertDictContainsSubset(return_value, res['member'])

    def test_member_get(self):
        def get_member(*args, **kwargs):
            return self.loadbalancer.get_member(*args, **kwargs)

        self.plugin.return_value.get_member.side_effect = get_member

        member_id = _uuid()
        pool_id = _uuid()

        pool = self._create_pool(pool_id)
        member = self._create_member(member_id, pool_id)

        instance = self.api_server
        instance.loadbalancer_pool_read.return_value = pool
        instance.loadbalancer_member_read.return_value = member

        res = self.api.get(_get_path('lb/members', id=member_id,
                                     fmt=self.fmt))

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('member', res)
        return_value = {'admin_state_up': True,
                        'tenant_id': pool.parent_uuid,
                        'status': "ACTIVE",
                        'id': member_id}
        self.assertDictContainsSubset(return_value, res['member'])

    def test_member_delete(self):
        def delete_member(*args, **kwargs):
            return self.loadbalancer.delete_member(*args, **kwargs)

        self.plugin.return_value.delete_member.side_effect = delete_member

        member_id = _uuid()
        res = self.api.delete(_get_path('lb/members', id=member_id,
                                        fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

        instance = self.api_server
        instance.loadbalancer_member_delete.assert_called_with(id=member_id)

    def test_health_monitor_create(self):
        def create_health_monitor(*args, **kwargs):
            return self.loadbalancer.create_health_monitor(*args, **kwargs)

        def api_loadbalancer_healthmonitor_create(*args, **kwargs):
            monitor = args[0]
            monitor.parent_uuid = self._project.uuid
            return monitor.uuid

        self.plugin.return_value.create_health_monitor.side_effect = \
            create_health_monitor

        instance = self.api_server
        instance.project_read.side_effect = self._project_read

        instance.loadbalancer_healthmonitor_create.side_effect = \
            api_loadbalancer_healthmonitor_create

        data = {'health_monitor': {'type': 'HTTP',
                                   'delay': 2,
                                   'timeout': 1,
                                   'max_retries': 3,
                                   'http_method': 'GET',
                                   'url_path': '/path',
                                   'expected_codes': '200-300',
                                   'admin_state_up': True,
                                   'tenant_id': _uuid()}}

        res = self.api.post(_get_path('lb/health_monitors',
                                      fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)

        health_monitor_id = res['health_monitor']['id']
        return_value = copy.copy(data['health_monitor'])
        return_value.update({'status': "ACTIVE", 'id': health_monitor_id})
        self.assertEqual(return_value, res['health_monitor'])

    def test_health_monitor_list(self):
        def get_health_monitors(*args, **kwargs):
            return self.loadbalancer.get_health_monitors(*args, **kwargs)

        self.plugin.return_value.get_health_monitors.side_effect = \
            get_health_monitors

        uuid1 = _uuid()
        uuid2 = _uuid()
        health_monitor_list = [
            {'fq_name': ['default-domain', 'test', uuid1], 'uuid': uuid1},
            {'fq_name': ['default-domain', 'test', uuid2], 'uuid': uuid2},
        ]
        instance = self.api_server
        instance.loadbalancer_healthmonitors_list.return_value = {
            'loadbalancer-healthmonitors': health_monitor_list
        }

        def loadbalancer_healthmonitor_read(*args, **kwargs):
            monitor = self._create_monitor(kwargs['id'], _uuid())
            return monitor

        instance.loadbalancer_healthmonitor_read.side_effect = \
            loadbalancer_healthmonitor_read

        res = self.api.get(_get_path('lb/health_monitors', fmt=self.fmt))

        res = self.deserialize(res)
        self.assertIn('health_monitors', res)
        self.assertEqual(2, len(res['health_monitors']))

    def test_health_monitor_update(self):
        def update_health_monitor(*args, **kwargs):
            return self.loadbalancer.update_health_monitor(*args, **kwargs)

        self.plugin.return_value.update_health_monitor.side_effect = \
            update_health_monitor

        health_monitor_id = _uuid()
        monitor = self._create_monitor(health_monitor_id, _uuid())

        instance = self.api_server
        instance.loadbalancer_healthmonitor_read.return_value = monitor

        update_data = {'health_monitor': {'admin_state_up': False}}

        res = self.api.put(_get_path('lb/health_monitors',
                                     id=health_monitor_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.loadbalancer_healthmonitor_update.assert_called_with(mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)

        return_value = {'type': 'HTTP',
                        'admin_state_up': False,
                        'tenant_id': monitor.parent_uuid,
                        'status': "ACTIVE",
                        'id': health_monitor_id}

        self.assertDictContainsSubset(return_value, res['health_monitor'])

    def test_health_monitor_get(self):
        def get_health_monitor(*args, **kwargs):
            return self.loadbalancer.get_health_monitor(*args, **kwargs)

        self.plugin.return_value.get_health_monitor.side_effect = \
            get_health_monitor

        health_monitor_id = _uuid()
        monitor = self._create_monitor(health_monitor_id, _uuid())

        instance = self.api_server
        instance.loadbalancer_healthmonitor_read.return_value = monitor

        res = self.api.get(_get_path('lb/health_monitors',
                                     id=health_monitor_id,
                                     fmt=self.fmt))

        self.assertEqual(res.status_int, exc.HTTPOk.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)

        return_value = {'type': 'HTTP',
                        'admin_state_up': True,
                        'tenant_id': monitor.parent_uuid,
                        'status': "ACTIVE",
                        'id': health_monitor_id}

        self.assertDictContainsSubset(return_value, res['health_monitor'])

    def test_health_monitor_delete(self):
        def delete_health_monitor(*args, **kwargs):
            return self.loadbalancer.delete_health_monitor(*args, **kwargs)

        self.plugin.return_value.delete_health_monitor.side_effect = \
            delete_health_monitor

        health_monitor_id = _uuid()
        res = self.api.delete(_get_path('lb/health_monitors',
                                        id=health_monitor_id,
                                        fmt=self.fmt))
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)

        instance = self.api_server
        instance.loadbalancer_healthmonitor_delete.assert_called_with(
            id=health_monitor_id)

    def test_create_pool_health_monitor(self):
        def create_pool_health_monitor(*args, **kwargs):
            return self.loadbalancer.create_pool_health_monitor(
                *args, **kwargs)

        self.plugin.return_value.create_pool_health_monitor.side_effect = \
            create_pool_health_monitor

        instance = self.api_server
        instance.project_read.side_effect = self._project_read

        tenant_id = _uuid()
        pool_id = _uuid()
        health_monitor_id = _uuid()

        pool = self._create_pool(pool_id, tenant_id)
        monitor = self._create_monitor(health_monitor_id, tenant_id)
        instance.loadbalancer_pool_read.return_value = pool
        instance.loadbalancer_healthmonitor_read.return_value = monitor

        data = {'health_monitor': {'id': health_monitor_id,
                                   'tenant_id': tenant_id}}

        res = self.api.post('/lb/pools/%s/health_monitors' % pool_id,
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)

        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('health_monitor', res)
        return_value = copy.copy(data['health_monitor'])
        self.assertEqual(return_value, res['health_monitor'])

    def test_delete_pool_health_monitor(self):
        def delete_pool_health_monitor(*args, **kwargs):
            return self.loadbalancer.delete_pool_health_monitor(
                *args, **kwargs)

        self.plugin.return_value.delete_pool_health_monitor.side_effect = \
            delete_pool_health_monitor

        tenant_id = _uuid()
        pool_id = _uuid()
        health_monitor_id = _uuid()

        pool = self._create_pool(pool_id, tenant_id)
        monitor = self._create_monitor(health_monitor_id, tenant_id)
        monitor.fq_name = ['default-domain', 'test', health_monitor_id]
        pool.add_loadbalancer_healthmonitor(monitor)

        instance = self.api_server
        instance.loadbalancer_pool_read.return_value = pool
        instance.loadbalancer_healthmonitor_read.return_value = monitor

        res = self.api.delete('/lb/pools/%s/health_monitors/%s' %
                              (pool_id, health_monitor_id))

        instance.loadbalancer_pool_update.assert_called_with(mock.ANY)
        self.assertEqual(res.status_int, exc.HTTPNoContent.code)
