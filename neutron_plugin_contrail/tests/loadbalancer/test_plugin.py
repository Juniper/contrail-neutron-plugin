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
from vnc_api.vnc_api import LoadbalancerPool
from vnc_api.vnc_api import Project
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
        def call(*args, **kwargs):
            return self.loadbalancer.create_vip(*args, **kwargs)

        def api_virtual_ip_create(*args, **kwargs):
            vip = args[0]
            vip.parent_uuid = self._project.uuid
            return vip

        self.plugin.return_value.create_vip.side_effect = call

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
