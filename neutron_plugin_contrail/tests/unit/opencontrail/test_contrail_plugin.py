# Copyright 2014 Juniper Networks.  All rights reserved.
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
import uuid

try:
    from oslo_config import cfg
except ImportError:
    from oslo.config import cfg

from neutron.api import extensions
from neutron.extensions import portbindings
from neutron.tests.unit import _test_extension_portbindings as test_bindings

try:
    from neutron.tests.unit import test_db_plugin as test_plugin
except ImportError:
    from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin

try:
    from neutron.tests.unit import test_extension_security_group as test_sg
except ImportError:
    from neutron.tests.unit.extensions import test_securitygroup as test_sg

try:
    from neutron.tests.unit import test_extensions
except ImportError:
    from neutron.tests.unit.api import test_extensions

try:
    from neutron.tests.unit import test_l3_plugin
except ImportError:
    from neutron.tests.unit.extensions import test_l3 as test_l3_plugin

from neutron_plugin_contrail.plugins.opencontrail.vnc_client import (
    contrail_res_handler)
from neutron_plugin_contrail.tests.unit.opencontrail.vnc_mock import MockVnc
from vnc_api import vnc_api

CONTRAIL_PKG_PATH = (
    "neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_v3")


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


class KeyStoneInfo(object):
    """To generate Keystone Authentication information.

       Contrail Driver expects Keystone auth info for testing purpose.
    """
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    auth_url = "http://localhost:5000/"
    auth_type = ""
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.NeutronPluginContrailCoreV3' % CONTRAIL_PKG_PATH)

    def setUp(self, plugin=None, ext_mgr=None):

        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        from neutron_plugin_contrail import extensions
        cfg.CONF.api_extensions_path = "extensions:" + extensions.__path__[0]
        res_handler = contrail_res_handler.ContrailResourceHandler
        res_handler._project_id_vnc_to_neutron = lambda x, y: y
        res_handler._project_id_neutron_to_vnc = lambda x, y: y
        vnc_api.VncApi = MockVnc
        self.domain_obj = vnc_api.Domain()
        MockVnc().domain_create(self.domain_obj)

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)

    def tearDown(self):
        MockVnc.resources_collection = dict()
        MockVnc._kv_dict = dict()
        super(JVContrailPluginTestCase, self).tearDown()


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailNetworksV2, self).setUp()

    def test_create_network_default_mtu(self):
        self.skipTest("Contrail doesn't support this feature yet")

    def test_create_network_vlan_transparent(self):
        self.skipTest("Contrail doesn't support this feature yet")


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailSubnetsV2, self).setUp()

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        self.skipTest("TODO: Not supported yet")

    def test_create_subnet_bad_tenant(self):
        self.skipTest("TODO: Investigate, why this fails in neutron itself")

    def test_create_subnet_ipv6_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_same_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_delete_subnet_port_exists_owned_by_other(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_port_prevents_subnet_deletion(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_router_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest("TODO: Very tough to mock this in vnc_mock")

    def test_create_subnet_ipv6_different_ra_and_addr_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_create_subnet_ipv6_ra_modes(self):
        self.skipTest("TODO: Investigate what needs to be done")

    def test_update_subnet(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_no_gateway(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_route_with_too_many_entries(self):
        self.skipTest("TODO: Investigate - support multiple host routes")

    def test_update_subnet_gw_ip_in_use_returns_409(self):
        self.skipTest("Contrail does not support updating gateway ip")

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_allocation_pools(self):
        self.skipTest("Contrail does not support updating allocation pools")

    def test_update_subnet_dns_with_too_many_entries(self):
        self.skipTest("TODO: Check why this should fail")

    # Support ipv6 in contrail is planned in Juno
    def test_create_subnet_ipv6_ra_mode_ip_version_4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_with_v6_allocation_pool(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_attributes_no_dhcp_enabled(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_attributes(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        self.skipTest("There is no dhcp port in contrail")

    def test_validate_subnet_host_routes_exhausted(self):
        self.skipTest("TODO : Need to revisit")

    def test_validate_subnet_dns_nameservers_exhausted(self):
        self.skipTest("TODO : Need to revisit")


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailPortsV2, self).setUp()
        self.port_create_status = 'DOWN'

    def test_requested_split(self):
        self.skipTest("TODO: Mocking complexity")

    def test_requested_invalid_fixed_ips(self):
        self.skipTest("TODO: Complete this functionality")

    def test_ip_allocation_for_ipv6_subnet_slaac_address_mode(self):
        self.skipTest("Not Supported yet")

    def test_requested_duplicate_mac(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_mac_exhaustion(self):
        self.skipTest("Specific to neutron")

    def test_mac_generation(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_mac_generation_4octet(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_bad_mac_format(self):
        self.skipTest("TODO: Failure because of base_mac setting")

    def test_update_port_not_admin(self):
        self.skipTest("TODO: Understand what this test cases is all about")

    def test_update_port_mac_bad_owner(self):
        self.skipTest("TODO: Understand what this test case is all about")

    def test_create_port_bad_tenant(self):
        self.skipTest("TODO: Investigate, why this fails in neutron itself")

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest("TODO: Investigate why this fails in neutron itself")

    def test_update_port_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("TODO: Investigate")

    def test_update_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest('Not Supported yet')

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest("Not Supported yet")

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        self.skipTest("Not Supported yet")

    def test_create_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("Not Supported yet")

    def test_update_port_mac_v6_slaac(self):
        self.skipTest("Not Supported yet")

    def test_update_port_excluding_ipv6_slaac_subnet_from_fixed_ips(self):
        self.skipTest('Not Supported yet')

    def test_delete_ports_by_device_id(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_by_device_id_second_call_failure(self):
        self.skipTest("This method tests rpc API of "
                      "which contrail isn't using")

    def test_delete_ports_ignores_port_not_found(self):
        self.skipTest("This method tests private method of "
                      "which contrail isn't using")


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 JVContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(TestContrailSecurityGroups, self).setUp(self._plugin_name,
                                                      ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_create_security_group_rule_duplicate_rule_in_post_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rule_db_emulated(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_duplicate_rules(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ethertype_for_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_rule_invalid_ip_prefix(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_security_group_source_group_ip_and_ip_prefix(self):
        self.skipTest("Investigation needed")

    def test_create_delete_security_group_port_in_use(self):
        self.skipTest("Investigation needed")


class TestContrailPortBinding(JVContrailPluginTestCase,
                              test_bindings.PortBindingsTestCase):
    # from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin
    # import (NeutronPluginContrailCoreV2)
    VIF_TYPE = portbindings.VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestContrailPortBinding, self).setUp()


class TestContrailL3NatTestCase(JVContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def setUp(self):
        super(TestContrailL3NatTestCase, self).setUp()

    def test_router_update_gateway_with_existed_floatingip(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        self.skipTest("Feature needs to be implemented")

    def test_two_fips_one_port_invalid_return_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_with_invalid_create_port(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_list_with_pagination_reverse(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_floatingip_no_ext_gateway_return_404(self):
        self.skipTest("Feature needs to be implemented")

    def test_create_router_port_with_device_id_of_other_teants_router(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_delete_subnet_inuse_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_network_update_external_failure(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_no_subnet_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_list_with_pagination(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_gateway_dup_subnet2_returns_400(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_with_assoc_fails(self):
        self.skipTest("Feature needs to be implemented")

    def test_floating_ip_direct_port_delete_returns_409(self):
        self.skipTest("Feature needs to be implemented")

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_create_call_extensions(self):
        self.skipTest("Feature needs to be implemented")

    def test_router_add_interface_subnet_with_port_from_other_tenant(self):
        self.skipTest("TODO : Need to revisit")

    def test_router_add_interface_subnet(self):
        self.skipTest("TODO : Need to revisit")

    def test_router_add_interface_dup_subnet1_returns_400(self):
        self.skipTest("TODO : Need to revisit")

    def test_floatingip_list_with_sort(self):
        self.skipTest("TODO : Need to revisit")

    def test_create_non_router_port_device_id_of_other_teants_router_update(
            self):
        self.skipTest("Contrail doesn't support this test case")
