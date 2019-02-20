import uuid

from cfgm_common.tests.test_common import TestCase
from cfgm_common.tests.test_utils import get_keystone_client
import mock
from neutron.api import extensions
# Mock patch eventlet monkey patching before importing neutron code
mock.patch('neutron.common.eventlet_utils.monkey_patch').start() # noqa
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit.api import test_extensions
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_plugin
from neutron.tests.unit.extensions import test_l3 as test_l3_plugin
from neutron.tests.unit.extensions import test_securitygroup as test_sg
from neutron_lib import context
from neutron_lib.plugins import directory
from oslo_config import cfg

from neutron_plugin_contrail.common.utils import register_vnc_api_options
from neutron_plugin_contrail.plugin.plugin_base import VIF_TYPE_VROUTER


PLUGIN_NAME = 'contrail'
original_uuid = uuid.UUID


def uuid_mock(*args, **kwargs):
    """Mock UUID method to allow fake UUID format used in UT."""
    try:
        return original_uuid(*args, **kwargs)
    except ValueError:
        if len(args) > 0 and isinstance(args[0], str):
            return args[0]
        raise


def get_tenant_mock(uuid):
    """Mock fate keystone client to populate tenants if not exists."""
    tenants = get_keystone_client().tenants
    try:
        tenants._tenants[uuid]
    except KeyError:
        tenants.add_tenant(uuid, uuid)
        return tenants._tenants[uuid]


class ContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase, TestCase):
    _config_knobs = [
        ('DEFAULTS', '', ''),
        ('KEYSTONE', 'admin_user', ''),
        ('KEYSTONE', 'admin_password', ''),
        ('KEYSTONE', 'admin_tenant_name', ''),
        ('KEYSTONE', 'admin_token', ''),
        ('KEYSTONE', 'auth_host', ''),
        ('KEYSTONE', 'auth_port', ''),
        ('KEYSTONE', 'auth_protocol', 'http'),
    ]

    @classmethod
    def setUpClass(cls, *args, **kwargs):
        mock.patch('keystoneclient.client.Client',
                   side_effect=get_keystone_client).start()
        mock.patch('uuid.UUID', side_effect=uuid_mock).start()
        super(ContrailPluginTestCase, cls).setUpClass(*args, **kwargs)

    def setUp(self, plugin=None, ext_mgr=None):
        # NOTE(ethuleau): not understand why I had to move all mocking stuff in
        #                 setUp instead of setUpClass to make it work
        mock.patch('vnc_cfg_api_server.vnc_db.VncDbClient._uuid_to_longs',
                   return_value={'uuid_mslong': 0, 'uuid_lslong': 0}).start()
        mock.patch('vnc_cfg_api_server.vnc_cfg_api_server.VncApiServer.'
                   'invalid_uuid', return_value=False).start()
        mock.patch('keystoneclient.client.Client',
                   side_effect=get_keystone_client).start()
        mock.patch(
            'cfgm_common.tests.test_utils.FakeKeystoneClient.Tenants.get',
            side_effect=get_tenant_mock).start()
        register_vnc_api_options()
        cfg.CONF.set_default('api_server_ip', self._api_server_ip,
                             group='APISERVER')
        cfg.CONF.set_default('api_server_port',
                             self._api_server._args.listen_port,
                             group='APISERVER')
        super(ContrailPluginTestCase, self).setUp(plugin=PLUGIN_NAME)
        mock.patch('uuid.UUID', side_effect=uuid_mock).start()
        self.admin_context = context.get_admin_context()
        self.admin_context.tenant_id = 'fake_admin_id'
        self.plugin = directory.get_plugin()
        origin_encode_context = directory.get_plugin()._encode_context

        def encode_context_mock(context, operation, apitype):
            project_id = getattr(context, 'project_id',
                                 getattr(context, 'tenant_id',
                                         'default-project'))
            context.project_id = context.tenant_id = project_id
            return origin_encode_context(context, operation, apitype)
        mock.patch.object(self.plugin, '_encode_context',
                          side_effect=encode_context_mock).start()


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             ContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(TestContrailNetworksV2, self).setUp()
        for net in self._list('networks')['networks']:
            if net['name'] not in ['ip-fabric', '__link_local__',
                                   'default-virtual-network', 'dci-network']:
                self._delete('networks', net['id'])

    def test_create_networks_bulk_emulated_plugin_failure(self):
        self.skipTest("Contrail plugin bug with create bulk")

    def test_create_networks_bulk_wrong_input(self):
        self.skipTest("Contrail plugin bug with create bulk")

    def test_list_networks(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_list_networks_with_fields(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_list_networks_with_pagination_emulated(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_list_networks_with_pagination_reverse_emulated(self):
        self.skipTest("Contrail plugin doesn't support pagination")

    def test_list_networks_with_parameters(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_list_networks_with_sort_emulated(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        self.skipTest("Contrail plugin bug: list return system VN "
                      "(ip-fabric...)")

    def test_update_network_set_not_shared_other_tenant_access_via_rbac(self):
        self.skipTest("Contrail plugin doesn't support Neutron RBAC")


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2, ContrailPluginTestCase):
    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_bad_V4_cidr_prefix_len(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_bad_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
            self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_dhcpv6_stateless_with_port_on_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_gw_outside_cidr_returns_201(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_gw_values(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_addr_modes(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_address_mode_ip_version_4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_attributes_no_dhcp_enabled(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_different_ra_and_addr_modes(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_gw_is_nw_end_addr_returns_201(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_gw_values(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_out_of_cidr_global(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_out_of_cidr_lla(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_pd_gw_values(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_ra_mode_ip_version_4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_ra_modes(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_same_ra_and_addr_modes(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_slaac_with_dhcp_port_on_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_slaac_with_port_not_found(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_slaac_with_port_on_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_no_cidr_and_default_subnetpool(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_nonzero_cidr(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_only_ip_version_v6_no_pool(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_with_cidr_and_default_subnetpool(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_with_network_different_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnets_native_quotas(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_ipv6_slaac_port_exists(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_port_exists_owned_by_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_with_callback(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_with_other_subnet_on_network_still_in_use(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_subnet_with_route(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_get_subnets_count(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_get_subnets_count_filter_by_project_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_get_subnets_count_filter_by_unknown_filter(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_ip_address(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_ip_version(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_uuid(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_filtering_by_project_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_shared(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_with_pagination_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_with_pagination_reverse_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_with_parameter(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_with_sort_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_port_prevents_network_deletion(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_port_prevents_subnet_deletion(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_show_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_subnet_lifecycle_dns_retains_order(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_subnet_update_ipv4_and_ipv6_pd_slaac_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_subnet_update_ipv4_and_ipv6_pd_v6stateless_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_subnet_usable_after_update(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_subnet_with_allocation_range(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_unsupported_subnet_cidr_loopback(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_unsupported_subnet_cidr_multicast(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools_and_gateway_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools_invalid_pool_for_cidr(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools_invalid_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools_over_gateway_ip_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_allocation_pools_overlapping_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_dns(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_dns_to_None(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_dns_with_too_many_entries(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_from_gw_to_new_gw(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_from_gw_to_no_gw(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_from_no_gw_to_no_gw(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_gw_ip_in_use_by_router_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_gw_outside_cidr_returns_200(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_address_mode_fails(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_address_mode_ip_version_4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_attributes_fails(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_cannot_disable_dhcp(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_ra_mode_fails(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_ipv6_ra_mode_ip_version_4(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_no_gateway(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_route(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_route_to_None(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_route_with_too_many_entries(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_subnet_shared_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_validate_subnet_dns_nameservers_exhausted(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_validate_subnet_host_routes_exhausted(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_bulk_create_subnet_ipv6_auto_addr_with_port_on_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_invalid_gw_V4_cidr(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_first_ip_owned_by_non_router(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_first_ip_owned_by_router(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_gw_is_nw_end_addr(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_gw_is_nw_start_addr(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_subnet_ipv6_gw_is_nw_start_addr_canonicalize(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_subnets_filtering_by_cidr_used_on_create(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")


class TestContrailPortsV2(test_plugin.TestPortsV2, ContrailPluginTestCase):
    def test_create_port_None_values(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_anticipating_allocation(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_as_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_bad_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_json(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_public_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_public_network_with_invalid_ip_and_subnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_public_network_with_invalid_ip_no_subnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_public_network_with_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_with_ipv6_dhcp_stateful_subnet_in_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_with_ipv6_pd_subnet_in_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_with_multiple_ipv4_and_ipv6_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_ports_bulk_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_ports_bulk_emulated_plugin_failure(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_ports_bulk_wrong_input(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_ports_native_quotas(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_router_port_ipv4_and_ipv6_slaac_no_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_network_if_port_exists(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_network_port_exists_owned_by_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_network_port_exists_owned_by_network_port_not_found(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_network_port_exists_owned_by_network_race(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_port_by_network_owner(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_port_public_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_port_with_ipv6_slaac_address(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_ports_by_device_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_ports_by_device_id_second_call_failure(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_ports_ignores_port_not_found(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_dhcp_port_ips_prefer_next_available_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_duplicate_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_duplicate_mac_generation(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_fixed_ip_invalid_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_fixed_ip_invalid_subnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_get_ports_count(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_admin_state(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_invalid_mac_address(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_ip_allocation_for_ipv6_2_subnet_slaac_mode(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_ip_allocation_for_ipv6_subnet_slaac_address_mode(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_is_mac_in_use(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_filtered_by_fixed_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_for_network_owner(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_public_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_with_pagination_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_with_pagination_reverse_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_with_sort_emulated(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_mac_generation(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_mac_generation_4octet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_no_more_port_exception(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_overlapping_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_port_update_with_ipam_error(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_range_allocation(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_duplicate_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_duplicate_mac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_fixed_ip_address_v6_slaac_router_iface(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_invalid_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_ips_only(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_subnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_subnet_id_not_on_network(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_subnet_id_v4_and_v6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_subnet_id_v4_and_v6_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_requested_subnet_id_v6_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_show_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_device_id_null(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_device_id_unchanged(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_add_additional_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_delete_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_excluding_ipv6_slaac_subnet_from_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_invalid_fixed_ip_address_v6_pd_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_invalid_fixed_ip_address_v6_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_invalid_subnet_v6_pd_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_mac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_mac_bad_owner(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_mac_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_mac_used(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_mac_v6_slaac(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_not_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_update_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_update_ip_address_only(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_update_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_with_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_with_new_ipv6_slaac_subnet_in_fixed_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_with_stale_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_filtered_by_fixed_ip_with_limit(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")


class TestContrailSubnetPoolsV2(test_plugin.TestSubnetPoolsV2,
                                ContrailPluginTestCase):
    def setUp(self):
        self.skipTest("Contrail does not support Neutron subnet pools core "
                      "API resource")


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 ContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        super(TestContrailSecurityGroups, self).setUp(PLUGIN_NAME, ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)

    def test_check_default_security_group_description(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_bad_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_bad_tenant_remote_group_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_bad_tenant_security_group_rule(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_duplicate_rules_proto_name_num(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_duplicate_rules_proto_num_name(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_icmp_with_code_only(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_icmpv6_legacy_protocol_name(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_icmpv6_with_type_only(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_protocol_as_number_range_bad(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_with_specific_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rules_native_quotas(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_groups_native_quotas(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_default_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_default_security_group_rules(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_default_security_group_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_delete_default_security_group_nonadmin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_ports_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_group_rules(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_group_rules_with_pagination(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_group_rules_with_pagination_reverse(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_group_rules_with_sort(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_groups(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_groups_with_pagination(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_groups_with_pagination_reverse(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_list_security_groups_with_sort(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_security_group_list_creates_default_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_security_group_port_create_creates_default_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_default_security_group_name_fail(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_default_security_group_with_description(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_remove_security_group_empty_list(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_remove_security_group_none(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_with_security_group(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_protocol_as_number_port_bad(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rules_admin_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_get_security_group_empty_rules(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_num(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_security_group_rule_ipv6_icmp_legacy_protocol_name(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")


class TestContrailPortBindings(test_bindings.PortBindingsTestCase,
                               ContrailPluginTestCase):
    VIF_TYPE = VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestContrailPortBindings, self).setUp()

    def test_port_update_portinfo_non_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_port_vif_details(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_ports_vif_details(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_binding_profile_none(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_port_binding_profile_with_empty_dict(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_binding_profile_none(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_binding_profile_with_empty_dict(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")


class TestContrailL3NatTestCase(ContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def test__notify_subnetpool_address_scope_update(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_ipv6_only_network_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_no_ext_gateway_return_404(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_assoc(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_assoc_to_ipv4_and_ipv6_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_assoc_to_ipv6_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_multisubnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_specific_ip_out_of_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_subnet_and_invalid_fip_address(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingip_with_wrong_subnet_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_floatingips_native_quotas(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_multiple_floatingips_same_fixed_ip_same_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_non_router_port_device_id_of_other_tenants_router_update(
            self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_router_gateway_fails(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_create_router_port_with_device_id_of_other_tenants_router(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_first_floatingip_associate_notification(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floating_ip_direct_port_delete_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floating_port_status_not_applicable(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_crd_ops(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_delete_router_intf_with_port_id_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_delete_router_intf_with_subnet_id_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_disassociate_notification(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_list_with_pagination(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_list_with_pagination_reverse(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_list_with_sort(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_multi_external_one_internal(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_same_external_and_internal(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_different_fixed_ip_same_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_different_port_owner_as_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_different_router(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_invalid_fixed_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_same_fixed_ip_same_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_subnet_gateway_disabled(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_update_to_same_port_id_twice(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_via_router_interface_returns_201(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_via_router_interface_returns_404(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_with_assoc_fails(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_floatingip_with_invalid_create_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_janitor_clears_orphaned_floatingip_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_janitor_doesnt_delete_if_fixed_in_interim(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_janitor_updates_port_device_id(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_network_update_external_failure(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_dup_subnet1_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_dup_subnet2_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_multiple_subnets_ipv6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_net_not_external_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_no_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_no_subnet_forbidden(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_iface_ipv6_ext_ra_subnet_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_by_port_admin_address_out_of_pool(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_by_port_cidr_overlapped_with_gateway(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_by_port_other_tenant_address_in_pool(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_by_port_other_tenant_address_out_of_pool(
            self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_by_subnet_other_tenant_subnet_returns_400(
            self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_cidr_overlapped_with_gateway(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_delete_port_after_failure(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_dup_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_dup_subnet1_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_dup_subnet2_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_ipv6_port_existing_network_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_ipv6_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_ipv6_subnet_without_gateway_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_multiple_ipv4_subnet_port_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_multiple_ipv4_subnets(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_multiple_ipv6_subnet_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_multiple_ipv6_subnets_different_net(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_multiple_ipv6_subnets_same_net(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_overlapped_cidr_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_port(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_port_bad_tenant_returns_404(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_port_without_ips(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_subnet_with_port_from_other_tenant(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_interface_with_both_ids_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_clear_gateway_callback_failure_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_concurrent_delete_upon_subnet_create(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create_call_extensions(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create_with_gwinfo(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create_with_gwinfo_ext_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create_with_gwinfo_ext_ip_non_admin(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_create_with_gwinfo_ext_ip_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_callback(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_dhcpv6_stateless_subnet_inuse_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_ipv6_slaac_subnet_inuse_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_race_with_interface_add(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_subnet_inuse_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_with_floatingip_existed_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_delete_with_port_existed_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_list(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_list_with_pagination(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_list_with_pagination_reverse(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_list_with_parameters(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_list_with_sort(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_callback_failure_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_inuse_returns_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_nothing_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_returns_200(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_with_both_ids_returns_200(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_wrong_port_returns_404(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_interface_wrong_subnet_returns_400(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_remove_ipv6_subnet_from_interface(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_show(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_specify_id_backend(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_add_multiple_prefixes_ipv6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_to_empty_with_existed_floatingip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_upon_subnet_create_ipv6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_upon_subnet_create_max_ips_ipv6(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_with_different_external_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_with_existed_floatingip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_with_external_ip_used_by_gw(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_with_invalid_external_ip(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_update_gateway_with_invalid_external_subnet(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_two_fips_one_port_invalid_return_409(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_update_port_device_id_to_different_tenants_router(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")

    def test_router_add_gateway_notifications(self):
        self.skipTest("Contrail plugin bug or not supported, need to be "
                      "checked")
