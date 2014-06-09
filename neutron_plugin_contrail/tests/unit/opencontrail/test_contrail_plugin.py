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
import json
import uuid

import mock
import netaddr
from oslo.config import cfg
import webob.exc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base as api_base
from neutron.common import exceptions as exc
from neutron import context as neutron_context
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import securitygroups_db
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_extensions
from neutron.tests.unit import test_l3_plugin


CONTRAIL_PKG_PATH = "neutron.plugins.opencontrail.contrail_plugin_core"


class FakeServer(db_base_plugin_v2.NeutronDbPluginV2,
                 external_net_db.External_net_db_mixin,
                 securitygroups_db.SecurityGroupDbMixin,
                 l3_db.L3_NAT_db_mixin):
    supported_extension_aliases = ['external-net', 'router', 'floatingip']

    @property
    def _core_plugin(self):
        return self

    def update_subnet(self, context, id, subnet):
        updated_subnet = super(
            FakeServer, self).update_subnet(context, id, subnet)
        updated_subnet['dns_nameservers'] = [
            {'address': address}
            for address in updated_subnet.get('dns_nameservers', [])]
        updated_subnet['routes'] = updated_subnet.get('host_routes', [])
        return updated_subnet

    def create_port(self, context, port):
        self._ensure_default_security_group_on_port(context, port)
        sgids = self._get_security_groups_on_port(context, port)
        result = super(FakeServer, self).create_port(context, port)
        self._process_port_create_security_group(context, result, sgids)
        return result

    def update_port(self, context, id, port):
        original_port = self.get_port(context, id)
        updated_port = super(FakeServer, self).update_port(context, id, port)
        port_updates = port['port']
        if ext_sg.SECURITYGROUPS in port_updates:
            port_updates[ext_sg.SECURITYGROUPS] = (
                self._get_security_groups_on_port(context, port))
            self._delete_port_security_group_bindings(context, id)
            self._process_port_create_security_group(
                context,
                updated_port,
                port_updates[ext_sg.SECURITYGROUPS])
        else:
            updated_port[ext_sg.SECURITYGROUPS] = (
                original_port[ext_sg.SECURITYGROUPS])

        return updated_port

    def delete_port(self, context, id, l3_port_check=True):
        if l3_port_check:
            self.prevent_l3_port_deletion(context, id)
        self.disassociate_floatingips(context, id)
        super(FakeServer, self).delete_port(context, id)

    def create_network(self, context, network):
        net_data = network['network']
        tenant_id = self._get_tenant_id_for_create(context, net_data)
        self._ensure_default_security_group(context, tenant_id)
        result = super(FakeServer, self).create_network(context, network)
        self._process_l3_create(context, result, network['network'])
        return result

    def update_network(self, context, id, network):
        with context.session.begin(subtransactions=True):
            result = super(
                FakeServer, self).update_network(context, id, network)
            self._process_l3_update(context, result, network['network'])
        return result

    def delete_network(self, context, id):
        self.delete_disassociated_floatingips(context, id)
        super(FakeServer, self).delete_network(context, id)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group.get('description')}
        res['rules'] = [
            self._make_security_group_rule_dict(r)
            for r in security_group.get('rules', [])]
        return self._fields(res, fields)

    def _make_subnet_dict(self, subnet, fields=None):
        res = {'id': subnet['id'],
               'name': subnet['name'],
               'tenant_id': subnet['tenant_id'],
               'network_id': subnet['network_id'],
               'ip_version': subnet['ip_version'],
               'cidr': subnet['cidr'],
               'allocation_pools': [{'first_ip': pool['first_ip'],
                                     'last_ip': pool['last_ip']}
                                    for pool in subnet['allocation_pools']],
               'gateway_ip': subnet['gateway_ip'],
               'enable_dhcp': subnet['enable_dhcp'],
               'ipv6_ra_mode': subnet['ipv6_ra_mode'],
               'ipv6_address_mode': subnet['ipv6_address_mode'],
               'dns_nameservers': [{'address': dns['address']}
                                   for dns in subnet['dns_nameservers']],
               'routes': [{'destination': route['destination'],
                           'nexthop': route['nexthop']}
                          for route in subnet['routes']],
               'shared': subnet['shared']
               }
        return self._fields(res, fields)

    def _make_network_dict(self, network, fields=None,
                           process_extensions=True):
        res = {'id': network['id'],
               'name': network['name'],
               'tenant_id': network['tenant_id'],
               'admin_state_up': network['admin_state_up'],
               'status': network['status'],
               'shared': network['shared'],
               'subnets': [self._make_subnet_dict(subnet)
                           for subnet in network['subnets']]}
        # Call auxiliary extend functions, if any
        if process_extensions:
            self._apply_dict_extend_functions(
                attr.NETWORKS, res, network)
        return self._fields(res, fields)

    def request(self, *args, **kwargs):
        request_data = json.loads(kwargs['data'])
        context_dict = request_data['context']
        context = neutron_context.Context.from_dict(context_dict)
        resource_type = context_dict['type']
        operation = context_dict['operation']
        data = request_data['data']
        resource = None
        if data.get('resource'):
            body = data['resource']
            if resource_type not in [
                    'security_group_rule', 'router', 'floatingip']:
                for key, value in body.items():
                    if value is None:
                        body[key] = attr.ATTR_NOT_SPECIFIED
            resource = {resource_type: body}

        obj = {}
        code = webob.exc.HTTPOk.code
        try:
            if operation == 'READ':
                func = getattr(self, 'get_%s' % resource_type)
                obj = func(context, data['id'])
            if operation == 'READALL':
                func = getattr(self, 'get_%ss' % resource_type)
                obj = func(context, filters=data.get('filters'))
            if operation == 'READCOUNT':
                func = getattr(self, 'get_%ss_count' % resource_type)
                count = func(context, filters=data.get('filters'))
                obj = {'count': count}
            if operation == 'CREATE':
                func = getattr(self, 'create_%s' % resource_type)
                obj = func(context, resource)
            if operation == 'UPDATE':
                func = getattr(self, 'update_%s' % resource_type)
                obj = func(context, data['id'], resource)
            if operation == 'DELETE':
                func = getattr(self, 'delete_%s' % resource_type)
                obj = func(context, data['id'])
            if operation == 'ADDINTERFACE':
                obj = self.add_router_interface(
                    context, data['id'], data['resource'])
            if operation == 'DELINTERFACE':
                obj = self.remove_router_interface(
                    context, data['id'], data['resource'])
        except (exc.NeutronException,
                netaddr.AddrFormatError) as e:
            for fault in api_base.FAULT_MAP:
                if isinstance(e, fault):
                    mapped_exc = api_base.FAULT_MAP[fault]
                    code = mapped_exc.code
            obj = {'type': e.__class__.__name__,
                   'message': e.msg, 'detail': ''}
            if data.get('id'):
                obj['id'] = data.get('id')
        response = mock.MagicMock()
        response.status_code = code
        response.content = json.dumps(obj)
        return response


FAKE_SERVER = FakeServer()


def init_mock():
    mock.patch('requests.post').start().side_effect = FAKE_SERVER.request


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


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.NeutronPluginContrailCoreV2' % CONTRAIL_PKG_PATH)

    def setUp(self, plugin=None, ext_mgr=None):

        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             JVContrailPluginTestCase):
    def setUp(self):
        init_mock()
        super(TestContrailNetworksV2, self).setUp()


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        init_mock()
        super(TestContrailSubnetsV2, self).setUp()

    # Support ipv6 in contrail
    def test_update_subnet_ipv6_attributes(self):
        pass

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        pass

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        pass

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        pass

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        # There is no dhcp port in contrail
        pass


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        init_mock()
        super(TestContrailPortsV2, self).setUp()

    def test_delete_ports_by_device_id(self):
        # This method tests rpc API of which contrail isn't using
        pass

    def test_delete_ports_by_device_id_second_call_failure(self):
        # This method tests rpc API of which contrail isn't using
        pass


class TestContrailSecurityGroups(test_sg.TestSecurityGroups,
                                 JVContrailPluginTestCase):
    def setUp(self, plugin=None, ext_mgr=None):
        init_mock()
        super(TestContrailSecurityGroups, self).setUp(self._plugin_name,
                                                      ext_mgr)
        ext_mgr = extensions.PluginAwareExtensionManager.get_instance()
        self.ext_api = test_extensions.setup_extensions_middleware(ext_mgr)


class TestContrailPortBinding(JVContrailPluginTestCase,
                              test_bindings.PortBindingsTestCase):
    VIF_TYPE = portbindings.VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        init_mock()
        super(TestContrailPortBinding, self).setUp()


class TestContrailL3NatTestCase(JVContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def setUp(self):
        init_mock()
        super(TestContrailL3NatTestCase, self).setUp()
