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
from testtools import matchers
import webob.exc

from neutron.api import extensions
from neutron.api.v2 import attributes as attr
from neutron.api.v2 import base as api_base
from neutron.common import exceptions as exc
from neutron import context as neutron_context
from neutron.db import api as db
from neutron.db import db_base_plugin_v2
from neutron.db import external_net_db
from neutron.db import l3_db
from neutron.db import quota_db  # noqa
from neutron.db import securitygroups_db
from neutron.extensions import portbindings
from neutron.extensions import securitygroup as ext_sg
from neutron.tests.unit import _test_extension_portbindings as test_bindings
from neutron.tests.unit import test_db_plugin as test_plugin
from neutron.tests.unit import test_extension_security_group as test_sg
from neutron.tests.unit import test_extensions
from neutron.tests.unit import test_l3_plugin


CONTRAIL_PKG_PATH = "neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_core"


class FakeServer(db_base_plugin_v2.NeutronDbPluginV2,
                 external_net_db.External_net_db_mixin,
                 securitygroups_db.SecurityGroupDbMixin,
                 l3_db.L3_NAT_db_mixin):
    """FakeServer for contrail api server.

    This class mocks behaviour of contrail API server.
    """
    supported_extension_aliases = ['external-net', 'router', 'floatingip']

    @property
    def _core_plugin(self):
        return self

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

        def return_obj():
            return obj
        response.json = return_obj
        return response


FAKE_SERVER = FakeServer()


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
        mock.patch('requests.post').start().side_effect = FAKE_SERVER.request
        db.configure_db()
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)


class TestContrailNetworksV2(test_plugin.TestNetworksV2,
                             JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailNetworksV2, self).setUp()


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailSubnetsV2, self).setUp()

    # Support ipv6 in contrail is planned in Juno
    def test_update_subnet_ipv6_attributes(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_address_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_enable_dhcp(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_update_subnet_ipv6_inconsistent_ra_attribute(self):
        self.skipTest("Contrail isn't supporting ipv6 yet")

    def test_delete_subnet_dhcp_port_associated_with_other_subnets(self):
        self.skipTest("There is no dhcp port in contrail")

    def _helper_test_validate_subnet(self, option, exception):
        cfg.CONF.set_override(option, 0)
        with self.network() as network:
            subnet = {'network_id': network['network']['id'],
                      'cidr': '10.0.2.0/24',
                      'ip_version': 4,
                      'tenant_id': network['network']['tenant_id'],
                      'gateway_ip': '10.0.2.1',
                      'dns_nameservers': ['8.8.8.8'],
                      'host_routes': [{'destination': '135.207.0.0/16',
                                       'nexthop': '1.2.3.4'}]}
            e = self.assertRaises(exception,
                                  FAKE_SERVER._validate_subnet,
                                  neutron_context.get_admin_context(
                                      load_admin_roles=False),
                                  subnet)
            self.assertThat(
                str(e),
                matchers.Not(matchers.Contains('built-in function id')))


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):
    def setUp(self):
        super(TestContrailPortsV2, self).setUp()

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


class TestContrailPortBinding(JVContrailPluginTestCase,
                              test_bindings.PortBindingsTestCase):
    from neutron_plugin_contrail.plugins.opencontrail.contrail_plugin_core import NeutronPluginContrailCoreV2
    VIF_TYPE = portbindings.VIF_TYPE_VROUTER
    HAS_PORT_FILTER = True

    def setUp(self):
        super(TestContrailPortBinding, self).setUp()


class TestContrailL3NatTestCase(JVContrailPluginTestCase,
                                test_l3_plugin.L3NatDBIntTestCase):
    mock_rescheduling = False

    def setUp(self):
        super(TestContrailL3NatTestCase, self).setUp()
