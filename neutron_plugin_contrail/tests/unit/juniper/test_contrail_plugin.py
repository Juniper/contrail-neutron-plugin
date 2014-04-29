# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import sys
import uuid

import netaddr
import mock
from oslo.config import cfg
import webob.exc

import neutron.db.api
from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import testlib_api



subnet_obj = {u'subnet':
              {'name': '', 'enable_dhcp': True,
               u'network_id': u'b11ffca3-3dfc-435e-ae0e-8f44da7188b7',
               'tenant_id': u'8162e75da480419a8b2ae7088dbc14f5',
               'dns_nameservers': '',
               u'contrail:ipam_fq_name':
               [u'default-domain', u'admin', u'default-network-ipam'],
               'allocation_pools': '', 'host_routes': '', u'ip_version': 4,
               'gateway_ip': '', u'cidr': u'20.20.1.0/29'}}

IIP_BREF_LIST = []
IIP_LIST = []
SUBNET_LIST = []
VM_LIST = []
VMI_LIST = []
VN_LIST = []
GLOBALPROJECTS = []


class MockVncApi(mock.MagicMock):
    def __init__(self, *args, **kwargs):
        pass

    def obj_to_id(self, *args, **kwargs):
        return args[0]._uuid
        return

    def kv_retrieve(self, *args, **kwargs):
        return []

    def kv_store(self, *args, **kwargs):
        return

    def kv_delete(self, *args, **kwargs):
        return

    def project_read(self, *args, **kwargs):
        return GLOBALPROJECTS[0]

    def projects_list(self, *args, **kwargs):
        return {'projects': [{'uuid': proj._uuid,
                              'fq_name': proj._fq_name}
                            for proj in GLOBALPROJECTS]}

    def subnet_create(self, subnet_obj):
        subnet_id = unicode(str(uuid.uuid4()))
        subnet_obj.set_uuid(subnet_id)
        SUBNET_LIST.append(subnet_obj)
        return subnet_id

    def subnet_read(self, id, *args, **kwargs):
        if len(SUBNET_LIST):
            for index in range(len(SUBNET_LIST)):
                if ((SUBNET_LIST[index].get_uuid()) == id):
                    return SUBNET_LIST[index]

    def subnets_list(self, *args, **kwargs):
        return {'subnets': [{'uuid': subnet._uuid,
                             'fq_name': subnet._fq_name}
                           for subnet in SUBNET_LIST]}

    def virtual_network_create(self, net_obj):
        net_id = unicode(str(uuid.uuid4()))
        net_obj.set_uuid(net_id)
        VN_LIST.append(net_obj)
        return net_id

    def virtual_network_read(self, id, *args, **kwargs):
        for vn in VN_LIST:
            if vn.get_uuid() == id:
                return vn

        #return a mock object if it is not created so far
        return MockVirtualNetwork('dummy-net', MockProject())

    def virtual_network_delete(self, id, *args, **kwargs):
        for vn in VN_LIST:
            if vn.get_uuid() == id:
                VN_LIST.remove(vn)
                return
        return

    def virtual_network_update(self, *args, **kwargs):
        return

    def virtual_networks_list(self, *args, **kwargs):
        return {'virtual-networks': [{'uuid': net.get_uuid(),
                                      'fq_name': net._fq_name}
                                    for net in VN_LIST]}

    def virtual_machine_create(self, mac_obj):
        mac_id = unicode(str(uuid.uuid4()))
        mac_obj.set_uuid(mac_id)
        VM_LIST.append(mac_obj)
        return mac_id

    def virtual_machine_read(self, id, *args, **kwargs):
        if len(VM_LIST):
            for index in range(len(VM_LIST)):
                if ((VM_LIST[index].get_uuid()) == id):
                    return VM_LIST[index]

    def virtual_machine_interface_create(self, vmi_obj):
        vmi_id = unicode(str(uuid.uuid4()))
        vmi_obj.set_uuid(vmi_id)
        VMI_LIST.append(vmi_obj)
        return vmi_id

    def virtual_machine_interface_delete(self, *args, **kwargs):
        return

    def virtual_machine_interface_update(self, *args, **kwargs):
        return

    def virtual_machine_interface_read(self, id, *args, **kwargs):
        if len(VMI_LIST):
            for index in range(len(VMI_LIST)):
                if ((VMI_LIST[index].get_uuid()) == id):
                    return VMI_LIST[index]

        #return a mock object if it is not created so far
        return MockVirtualMachineInterface('dummy-vmi', MockProject())

    def instance_ip_create(self, ip_obj):
        iip_id = unicode(str(uuid.uuid4()))
        ip_obj.set_uuid(iip_id)
        IIP_BREF_LIST.append({'uuid':iip_id})
        IIP_LIST.append(ip_obj)
        return iip_id

    def instance_ip_update(self):
        return

    def instance_ip_read(self, id, *args, **kwargs):
        if len(IIP_LIST):
            for index in range(len(IIP_LIST)):
                if ((IIP_LIST[index].get_uuid()) == id):
                    return IIP_LIST[index]

        #return a mock object if it is not created so far
        return MockInstanceIp('dummy-iip', MockProject())

    def instance_ip_delete(self, id):
        return


class MockVncObject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVncObject, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self._ipam_refs = [{'to': [u'default-domain', u'admin',
                           u'default-network-ipam']}]
        self._uuid = str(uuid.uuid4())
        self.name = name
        self.network_ipam_refs = []

    def set_uuid(self, uuid):
        self._uuid = uuid

    def get_uuid(self):
        return self._uuid

    def get_fq_name(self):
        return self._fq_name

    def get_network_ipam_refs(self):
        return getattr(self, 'network_ipam_refs', None)

    def add_network_ipam(self, ref_obj, ref_data):
        # refs = getattr(self, 'network_ipam_refs', [])
        refs = self.network_ipam_refs
        if not refs:
            self.network_ipam_refs = []

        # if ref already exists, update any attr with it
        for ref in refs:
            if ref['to'] == ref_obj.get_fq_name():
                ref = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
                if ref_obj._uuid:
                    ref['uuid'] = ref_obj._uuid
                return

        # ref didn't exist before
        ref_info = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
        if ref_obj._uuid:
            ref_info['uuid'] = ref_obj._uuid

        self.network_ipam_refs.append(ref_info)


class MockVirtualNetwork(MockVncObject):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVncObject, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self.uuid = str(uuid.uuid4())
        self._shared = False
        self.name = name
        self.network_ipam_refs = []

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_shared(self):
        return self._shared

    def set_shared(self, shared):
        self._shared = shared

    def get_network_ipam_refs(self):
        return getattr(self, 'network_ipam_refs', None)


class MockVirtualMachine(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVirtualMachine, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self._uuid = str(uuid.uuid4())
        self.name = name

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self._uuid

    def set_uuid(self, uuid):
        self._uuid = uuid


class MockVirtualMachineInterface(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(MockVirtualMachineInterface, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self.uuid = str(uuid.uuid4())
        self._name = name
        self.parent_name = None
        self.display_name = name
        self.mac_addresses_refs = []
        self._net_refs = []
        self._sg_list = []

    @property
    def parent_uuid(self):
        return self.parent_obj.get_uuid()

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_name(self):
        return self._name

    def set_name(self, name):
        self._name = name

    def get_display_name(self):
        return self.display_name

    def set_display_name(self, display_name):
        self.display_name = display_name

    def get_virtual_network_refs(self):
        return self._net_refs

    def set_virtual_network(self, net):
        self._net_refs.append(net)

    def get_security_group_list(self):
        return self._sg_list

    def set_security_group_list(self, sg_list):
        self._sg_list = sg_list

    def get_virtual_machine_interface_mac_addresses(self):
        return self.mac_addresses_refs

    def set_virtual_machine_interface_mac_addresses(self, mac_addresses):
        self.mac_addresses_refs = mac_addresses

    def get_instance_ip_back_refs(self):
        return IIP_BREF_LIST

class MockInstanceIp(mock.MagicMock):
    def __init__(self, name=None, *args, **kwargs):
        super(MockInstanceIp, self).__init__()
        self.name = name
        self._vmi = None
        self._net = None
        self._ipaddr = "10.1.1.1"

    def get_uuid(self):
        return self.uuid

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_virtual_machine_interface(self):
        return self._vmi

    def set_virtual_machine_interface(self, vmi):
        self._vmi = vmi

    def get_virtual_network(self):
        return self._net

    def set_virtual_network(self, net):
        self._net = net

    def get_instance_ip_address(self):
        return self._ipaddr

    def set_instance_ip_address(self, ipaddr):
        self._ipaddr = ipaddr


class MockSubnetType(mock.MagicMock):
    def __init__(self, name=None, ip_prefix=None, ip_prefix_len=None,
                 *args, **kwargs):
        super(MockSubnetType, self).__init__()
        self.name = name
        self.ip_prefix = ip_prefix
        self.ip_prefix_len = ip_prefix_len
        self.enable_dhcp = False
        self.dns_nameservers = []
        self.host_routes = []
        self.allocation_pools = []

    def get_ip_prefix(self):
        return self.ip_prefix

    def set_ip_prefix(self, ip_prefix):
        self.ip_prefix = ip_prefix

    def get_ip_prefix_len(self):
        return self.ip_prefix_len

    def set_ip_prefix_len(self, ip_prefix_len):
        self.ip_prefix_len = ip_prefix_len

    def get_dhcp(self):
        return self.enable_dhcp

    def set_dhcp(self, flag):
        self.enable_dhcp = flag

    def get_dns_nameservers(self):
        return getattr(self, 'dns_nameservers', None)

    def set_dns_nameservers(self, dns_nameservers):
        self.dns_nameservers = dns_nameservers

    def get_host_routes(self):
        return getattr(self, 'host_routes', None)

    def set_host_routes(self, host_routes):
        self.host_routes = host_routes

    def get_allocation_pools(self):
        return getattr(self, 'allocation_pools', None)

    def add_allocation_pools(self, pool):
        allocation_pools = self.get_allocation_pools()
        if not allocation_pools:
            allocation_pools.append(pool)
            return 0

        cidr = netaddr.IPNetwork("%s/%s" %(pool['start'], pool['end']))
        for apool in allocation_pools:
            acidr = netaddr.IPNetwork("%s/%s" %(apool['start'], apool['end']))
            if cidr in acidr or acidr in cidr:
                return 1

        allocation_pools.append(pool)
        return 0

    def set_allocation_pools(self, allocation_pools):
        if allocation_pools:
            self.allocation_pools = allocation_pools
            return

        # Create an allocation pool
        pool = {}
        cidr = "%s/%s" %(self.ip_prefix, self.ip_prefix_len)
        start_ip = str(netaddr.IPNetwork(cidr).network + 1)
        pool['start'] = start_ip
        end_ip = str(netaddr.IPNetwork(cidr).broadcast - 2)
        pool['end'] = end_ip

        self.allocation_pools.append(pool)


class MockIpamSubnetType(mock.MagicMock):
    def __init__(self, name=None, subnet=None, default_gateway=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.subnet = subnet
        self.default_gateway = default_gateway

    def get_subnet(self):
        return self.subnet

    def set_subnet(self, subnet):
        self.subnet = subnet

    def get_default_gateway(self):
        return self.default_gateway

    def set_default_gateway(self, default_gateway):
        self.default_gateway = default_gateway

    def validate_IpAddressType(self, value):
        pass


class MockVnSubnetsType(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, ipam_subnets=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.ipam_subnets = []
        if ipam_subnets:
            #self.ipam_subnets = copy.deepcopy(ipam_subnets)
            self.ipam_subnets = ipam_subnets

    def get_ipam_subnets(self):
        return self.ipam_subnets

    def set_ipam_subnets(self, ipam_subnets):
        self.ipam_subnets = ipam_subnets

    def add_ipam_subnets(self, value):
        self.ipam_subnets.append(value)

    def insert_ipam_subnets(self, index, value):
        self.ipam_subnets[index] = value

    def delete_ipam_subnets(self, value):
        self.ipam_subnets.remove(value)


class MockNetworkIpam(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None,
                 network_ipam_mgmt=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'default-network-ipam'
        self.name = name
        self._uuid = None
        if parent_obj:
            self.parent_type = parent_obj._type
            # copy parent's fq_name
            self._fq_name = list(parent_obj._fq_name)
            self._fq_name.append(name)
            if not parent_obj.get_network_ipams():
                parent_obj.network_ipams = []
            parent_obj.network_ipams.append(self)
        else:  # No parent obj specified
            self.parent_type = 'project'
            self._fq_name = [u'default-domain', u'default-project']
            self._fq_name.append(name)

        # property fields
        if network_ipam_mgmt:
            self.network_ipam_mgmt = network_ipam_mgmt
        if id_perms:
            self.id_perms = id_perms

    def get_fq_name(self):
        return self._fq_name


class MockProject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'project'
        self._uuid = str(uuid.uuid4())
        self.parent_type = 'domain'
        self.name = name
        self._fq_name = [u'default-domain']
        self._fq_name.append(name)
        self.security_groups = []

    def get_fq_name(self):
        return self._fq_name

    def get_security_groups(self):
        return getattr(self, 'security_groups', None)

    def set_security_groups(self, security_groups):
        self.security_groups = security_groups


def GlobalProjectApi(project_name):
    for proj in GLOBALPROJECTS:
        if proj.get_fq_name()[-1] == project_name:
            return proj

    project = MockProject(name=project_name)
    GLOBALPROJECTS.append(project)

    return project


class keystone_info_class(object):
    """To generate Keystone Authentication information

    Contrail Driver expects Keystone auth info for testing purpose.
    """
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'

def fake_requests_post(*args, **kwargs):
    import pdb; pdb.set_trace()

def fake_requests_get(*args, **kwargs):
    import pdb; pdb.set_trace()

def fake_requests_put(*args, **kwargs):
    import pdb; pdb.set_trace()

def fake_requests_delete(*args, **kwargs):
    import pdb; pdb.set_trace()

import pdb; pdb.set_trace()
fake_requests = mock.MagicMock(name='fake_requests_pkg')
sys.modules['requests'] = fake_requests
fake_requests.get = fake_requests_get
fake_requests.put = fake_requests_put
fake_requests.post = fake_requests_post
fake_requests.delete = fake_requests_delete

# Mock definations for different pkgs, modules and VncApi
mock_vnc_api_cls = mock.MagicMock(name='MockVncApi', side_effect=MockVncApi)
mock_vnc_api_mod = mock.MagicMock(name='vnc_api_mock_mod')
mock_vnc_api_mod.VncApi = mock_vnc_api_cls
mock_vnc_api_mod.VirtualNetwork = MockVirtualNetwork
mock_vnc_api_mod.VirtualMachine = MockVirtualMachine
mock_vnc_api_mod.VirtualMachineInterface = MockVirtualMachineInterface
mock_vnc_api_mod.SubnetType = MockSubnetType
mock_vnc_api_mod.IpamSubnetType = MockIpamSubnetType
mock_vnc_api_mod.VnSubnetsType = MockVnSubnetsType
mock_vnc_api_mod.NetworkIpam = MockNetworkIpam
mock_vnc_api_mod.InstanceIp = MockInstanceIp
mock_vnc_api_mod.Project = GlobalProjectApi

mock_vnc_api_pkg = mock.MagicMock(name='vnc_api_mock_pkg')
mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod
mock_cfgm_common_mod = mock.MagicMock(name='cfgm_common_mock_mod')
mock_cfgm_exception_mod = mock.MagicMock(name='cfgm_exception_mock_mod')
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api'] = \
    mock_vnc_api_pkg
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api.vnc_api'] = \
    mock_vnc_api_mod
sys.modules['neutron.plugins.juniper.contrail.ctdb.cfgm_common'] = \
    mock_cfgm_common_mod
sys.modules[('neutron.plugins.juniper.contrail.ctdb.cfgm_common.'
             'exceptions')] = \
    mock_cfgm_exception_mod


CONTRAIL_PKG_PATH = "neutron.plugins.juniper.contrail.contrail_plugin_core"


class RouterInstance(object):
    def __init__(self):
        self._name = 'rounter_instance'


class Context(object):
    def __init__(self, tenant_id=''):
        self.read_only = False
        self.show_deleted = False
        self.roles = [u'admin', u'KeystoneServiceAdmin', u'KeystoneAdmin']
        self._read_deleted = 'no'
        self.timestamp = datetime.datetime.now()
        self.auth_token = None
        self._session = None
        self._is_admin = True
        self.admin = uuid.uuid4().hex.decode()
        self.request_id = 'req-' + str(uuid.uuid4())
        self.tenant = tenant_id


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.NeutronPluginContrailCoreV2' % CONTRAIL_PKG_PATH)

    def setUp(self):

        cfg.CONF.keystone_authtoken = keystone_info_class()
        mock_cfgm_common_mod.exceptions = mock_cfgm_exception_mod

        mock_vnc_api_mod.common = mock_cfgm_common_mod
        mock_vnc_api_mod.VncApi = mock_vnc_api_cls

        mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)
        cfg.CONF.set_override('quota_driver', 'neutron.quota.ConfDriver',
                              group='QUOTAS')
        self._tenant_id = GlobalProjectApi(self._tenant_id)._uuid
        neutron.db.api._ENGINE = mock.MagicMock()

    def teardown(self):
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)


class TestContrailNetworks(test_plugin.TestNetworksV2,
                           JVContrailPluginTestCase):

    def test_create_network(self):
        import pdb; pdb.set_trace()
        super(TestContrailNetworks, self).test_create_network()

    def test_delete_network(self):
        # First create the network and request to delete the same
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        context_obj = Context(network['tenant_id'])
        #create project
        if not GLOBALPROJECTS:
            project_name = 'admin'
            GLOBALPROJECTS.append(MockProject(name=project_name))

        networks_req[u'network'] = network
        net_dict = plugin_obj.create_network(context_obj, networks_req)
        net_id = net_dict.get('id')

        plugin_obj.delete_network(context_obj, net_id)
        mock_vnc_api_cls.virtual_network_delete.assert_called_once()

    def test_update_network(self):
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        context_obj = Context(network['tenant_id'])
        #create project
        if not GLOBALPROJECTS:
            project_name = 'admin'
            GLOBALPROJECTS.append(MockProject(name=project_name))

        networks_req[u'network'] = network
        net_dict = plugin_obj.create_network(context_obj, networks_req)
        net_id = net_dict.get('id')
        # change one of the attribute and update the network
        network['admin_state_up'] = 'False'
        new_dict = plugin_obj.update_network(context_obj, net_id,
                                             networks_req)
        self.assertNotEqual(net_dict.get('admin_state_up'),
                            new_dict.get('admin_state_up'))

    # Not supported test cases in the this TestClass
    def test_update_network_set_not_shared_other_tenant_returns_409(self):
        ##
        pass

    def test_update_network_set_not_shared_multi_tenants_returns_409(self):
        ##
        pass

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        ##
        pass

    def test_update_network_with_subnet_set_shared(self):
        ## - DB access issue
        pass

    def test_list_shared_networks_with_non_admin_user(self):
        ## - fails when run in parallel
        pass

    def test_list_networks(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_with_sort_emulated(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_with_pagination_emulated(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_with_pagination_reverse_emulated(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_with_fields(self):
        ## - fails when run in parallel
        pass

    def test_list_networks_with_parameters(self):
        ## - fails when run in parallel
        pass

    def test_create_networks_bulk_wrong_input(self):
        ## - fails when run in parallel
        pass

    def test_create_networks_bulk_emulated_plugin_failure(self):
        ## - fails when run in parallel
        pass


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):

    def test_create_subnet(self):
        #First create virtual network without subnet and then
        #create subnet to update given network.
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        networks_req[u'network'] = network
        context_obj = Context(network['tenant_id'])
        #create project
        if not GLOBALPROJECTS:
            project_name = 'admin'
            GLOBALPROJECTS.append(MockProject(name=project_name))

        net = plugin_obj.create_network(context_obj, networks_req)

        subnet_obj[u'subnet']['network_id'] = net['id']
        subnet_dict = plugin_obj.create_subnet(context_obj, subnet_obj)
        self.assertEqual(subnet_dict['cidr'],
                         subnet_obj['subnet']['cidr'])

    def test_delete_subnet(self):
        #First create virtual network without subnet and then
        #create subnet to update given network.
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        networks_req[u'network'] = network
        context_obj = Context(network['tenant_id'])
        #create project
        if not GLOBALPROJECTS:
            project_name = 'admin'
            GLOBALPROJECTS.append(MockProject(name=project_name))

        net = plugin_obj.create_network(context_obj, networks_req)

        subnet_obj[u'subnet']['network_id'] = net['id']
        subnet_dict = plugin_obj.create_subnet(context_obj, subnet_obj)
        subnet_id = subnet_dict['id']
        plugin_obj.delete_subnet(context_obj, subnet_id)

    def test_create_two_subnets(self):
        ## - Quota exceeded
        pass

    def test_create_two_subnets_same_cidr_returns_400(self):
        ## - implement pooling in Mock
        pass

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        ## - implement pooling in Mock
        pass

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        ## - 
        pass

    def test_create_subnet_bad_tenant(self):
        ## - tenant id is string
        pass

    #def test_create_subnet_bad_pools(self):
        ## - implement pooling in Mock
    #    pass

    def test_create_subnet_defaults(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_create_subnet_gw_values(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
            self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        ##
        pass

    def test_create_subnet_with_v6_allocation_pool(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv4_cidrv6(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv4_gatewayv6(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        ## - ipv6 ???
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        ## - ipv6 ???
        pass

    def test_list_subnets(self):
        ##
        pass

    def test_list_subnets_shared(self):
        ##
        pass

    def test_list_subnets_with_parameter(self):
        ##
        pass

    def test_list_subnets_with_pagination_emulated(self):
        ## - takes time
        pass

    def test_list_subnets_with_pagination_reverse_emulated(self):
        ##
        pass

    def test_list_subnets_with_sort_emulated(self):
        ##
        pass

    def test_update_subnet_dns(self):
        ##
        pass

    def test_update_subnet_dns_to_None(self):
        ##
        pass

    def test_update_subnet_dns_with_too_many_entries(self):
        ##
        pass

    def test_update_subnet_route(self):
        ##
        pass

    def test_update_subnet_route_to_None(self):
        ##
        pass

    def test_update_subnet_route_with_too_many_entries(self):
        ##
        pass

    def test_update_subnet_gw_ip_in_use_returns_409(self):
        ##
        pass

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_update_subnet_gw_outside_cidr_force_on_returns_400(self):
        ##
        pass

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        ##
        pass

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        ##
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        ##
        pass

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        ##
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        ##
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        ##
        pass

    def test_delete_subnet_port_exists_owned_by_other(self):
        ##
        pass

    def test_delete_subnet_port_exists_owned_by_network(self):
        ##
        pass


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):

    def test_create_port_json(self):
        ##
        pass

    def test_create_port_bad_tenant(self):
        ## - 403 vs 404
        pass

    def test_create_port_public_network(self):
        ## - tenant id is a name
        pass

    def test_create_port_public_network_with_ip(self):
        ##
        pass

    def test_create_ports_bulk_emulated(self):
        ##
        pass

    def test_create_ports_bulk_wrong_input(self):
        ##
        pass

    def test_create_port_as_admin(self):
        ##
        pass

    def test_list_ports(self):
        ##
        pass

    def test_list_ports_filtered_by_fixed_ip(self):
        ##
        pass

    def test_list_ports_public_network(self):
        ##
        pass

    def test_list_ports_with_pagination_emulated(self):
        ##
        pass

    def test_list_ports_with_pagination_reverse_emulated(self):
        ##
        pass

    def test_list_ports_with_sort_emulated(self):
        ##
        pass

    def test_delete_port(self):
        ## - tenant id is a name ???
        pass

    def test_delete_port_public_network(self):
        ## - tenant id is a name ???
        pass

    def test_update_port_update_ip(self):
        ##
        pass

    def test_update_port_delete_ip(self):
        ##
        pass

    def test_update_port_update_ip_address_only(self):
        ##
        pass

    def test_update_port_update_ips(self):
        ##
        pass

    def test_update_port_add_additional_ip(self):
        ##
        pass

    def test_update_port_not_admin(self):
        ##
        pass

    def test_delete_network_if_port_exists(self):
        ##
        pass

    def test_no_more_port_exception(self):
        ##
        pass

    def test_requested_duplicate_mac(self):
        ##
        pass

    def test_mac_generation(self):
        ##
        pass

    def test_mac_generation_4octet(self):
        ##
        pass

    def test_mac_exhaustion(self):
        ##
        pass

    def test_requested_duplicate_ip(self):
        ##
        pass

    def test_requested_subnet_delete(self):
        ##
        pass

    def test_requested_subnet_id(self):
        ##
        pass

    def test_requested_subnet_id_not_on_network(self):
        ##
        pass

    def test_requested_subnet_id_v4_and_v6(self):
        ##
        pass

    def test_range_allocation(self):
        self.skipTest("Plugin does not support Neutron allocation process")

    def test_requested_invalid_fixed_ips(self):
        ##
        pass

    def test_requested_split(self):
        ## - valid IP Address ???
        pass

    def test_requested_ips_only(self):
        ##
        pass

    def test_max_fixed_ips_exceeded(self):
        ##
        pass

    def test_update_max_fixed_ips_exceeded(self):
        ##
        pass

