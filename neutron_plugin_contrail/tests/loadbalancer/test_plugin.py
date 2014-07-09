import copy
from neutron.extensions import loadbalancer
from neutron.openstack.common import uuidutils
from neutron.plugins.common import constants
from neutron.tests.unit import test_api_v2
from neutron.tests.unit import test_api_v2_extension
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.plugin \
    import LoadBalancerPlugin
import mock
from vnc_api.vnc_api import VncApi
from vnc_api.vnc_api import IdPermsType
from vnc_api.vnc_api import LoadbalancerPool
from vnc_api.vnc_api import Project
from vnc_api.vnc_api import VirtualIp, VirtualIpType
from webob import exc

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

        plugin_path = '.'.join(_PLUGIN.split('.')[:-1])

        self._patcher = mock.patch('%s.VncApi' % plugin_path, autospec=True)
        self._patcher.start()
        self.loadbalancer = LoadBalancerPlugin()
        self.api_server = self.loadbalancer._api
        self._project = None

    def tearDown(self):
        self._patcher.stop()
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

        def api_virtual_ip_create(*args, **kwargs):
            vip = args[0]
            vip.parent_uuid = self._project.uuid
            return vip

        instance = self.api_server
        instance.fq_name_to_id.return_value = None
        instance.project_read.side_effect = \
            self._project_read
        instance.loadbalancer_pool_read.side_effect = \
            self._loadbalancer_pool_read
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
                         'port_id': None,
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
