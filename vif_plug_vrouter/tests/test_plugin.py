# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
import sys

import contextlib
import mock
import six
import testtools

from oslo_concurrency import processutils

from os_vif import objects

from vif_plug_vrouter import privsep
sys.modules['oslo_config'] = mock.Mock()
from vif_plug_vrouter import vrouter


if six.PY2:
    nested = contextlib.nested
else:
    @contextlib.contextmanager
    def nested(*contexts):
        with contextlib.ExitStack() as stack:
            yield [stack.enter_context(c) for c in contexts]


class PluginTest(testtools.TestCase):

    def __init__(self, *args, **kwargs):
        super(PluginTest, self).__init__(*args, **kwargs)

        objects.register_all()
        privsep.vif_plug.set_client_mode(False)

    subnet_bridge_4 = objects.subnet.Subnet(
        cidr='101.168.1.0/24',
        dns=['8.8.8.8'],
        gateway='101.168.1.1',
        dhcp_server='191.168.1.1')

    subnet_bridge_6 = objects.subnet.Subnet(
        cidr='101:1db9::/64',
        gateway='101:1db9::1')

    subnets = objects.subnet.SubnetList(
        objects=[subnet_bridge_4,
                 subnet_bridge_6])

    network_vrouter = objects.network.Network(
        id='network-id-xxx-yyy-zzz',
        bridge='br0',
        subnets=subnets,
        vlan=99)

    vif_vhostuser_vrouter = objects.vif.VIFVHostUser(id='vif-xxx-yyy-zzz',
        address='ca:fe:de:ad:be:ef',
        network=network_vrouter,
        path='/var/run/openvswitch/vhub679325f-ca',
        mode='client',
        vif_name='tapXXX')

    vif_vhostuser_no_path = objects.vif.VIFVHostUser(id='vif-xxx-yyy-zzz',
        address='ca:fe:de:ad:be:ef',
        network=network_vrouter,
        mode='client',
        vif_name='tapXXX')

    instance = objects.instance_info.InstanceInfo(name='Instance 1',
        uuid='f0000000-0000-0000-0000-000000000001', project_id='1')

    def test_ip_version(self):
        ip4 = vrouter.VrouterPlugin._ip_version('192.168.0.1')
        ip6 = vrouter.VrouterPlugin._ip_version('2001:660::1')
        ip_invalid = vrouter.VrouterPlugin._ip_version('invalid')

        self.assertEqual(ip4, 4)
        self.assertEqual(ip6, 6)
        self.assertEqual(ip_invalid, False)

    def test_vhostuser_vrouter_plug(self):
        calls = {
            '_vrouter_port_add': [mock.call(self.instance,
                                  self.vif_vhostuser_vrouter)]
        }
        with mock.patch.object(vrouter.VrouterPlugin,
                               '_vrouter_port_add') as port_add:
            plugin = vrouter.VrouterPlugin.load("vrouter")
            plugin.plug(self.vif_vhostuser_vrouter, self.instance)

            port_add.assert_has_calls(calls['_vrouter_port_add'])

    def test_vhostuser_vrouter_unplug(self):
        calls = {
            '_vrouter_port_delete': [mock.call(self.instance,
                                     self.vif_vhostuser_vrouter)]
        }
        with mock.patch.object(vrouter.VrouterPlugin,
                               '_vrouter_port_delete') as delete_port:
            plugin = vrouter.VrouterPlugin.load("vrouter")
            plugin.unplug(self.vif_vhostuser_vrouter, self.instance)

            delete_port.assert_has_calls(calls['_vrouter_port_delete'])

    def test_vrouter_port_add(self):
        ip_addr = '0.0.0.0'
        ip6_addr = None
        ptype = 'NovaVMPort'
        cmd_args = ("--oper=add --uuid=%s --instance_uuid=%s --vn_uuid=%s "
                    "--vm_project_uuid=%s --ip_address=%s --ipv6_address=%s "
                    "--vm_name=%s --mac=%s --tap_name=%s --port_type=%s "
                    "--vif_type=%s --vhostuser_socket=%s "
                    "--tx_vlan_id=%d --rx_vlan_id=%d" %
                    (self.vif_vhostuser_vrouter.id,
                    self.instance.uuid,
                    self.vif_vhostuser_vrouter.network.id,
                    self.instance.project_id, ip_addr, ip6_addr,
                    self.instance.name,
                    self.vif_vhostuser_vrouter.address,
                    self.vif_vhostuser_vrouter.vif_name, ptype, 'VhostUser',
                    self.vif_vhostuser_vrouter.path, -1, -1))
        calls = {
            'execute': [mock.call('vrouter-port-control', cmd_args)]
        }

        with mock.patch.object(processutils, 'execute') as execute_cmd:
            vrouter.VrouterPlugin._vrouter_port_add(self.instance, self.vif_vhostuser_vrouter)

            execute_cmd.assert_has_calls(calls['execute'])

    def test_vrouter_port_delete(self):
        cmd_args = ("--oper=delete --uuid=%s" %
                    (self.vif_vhostuser_vrouter.id))
        calls = {
            'execute': [mock.call('vrouter-port-control', cmd_args)]
        }

        with mock.patch.object(processutils, 'execute') as execute_cmd:
            vrouter.VrouterPlugin._vrouter_port_delete(self.instance,
                    self.vif_vhostuser_vrouter)

            execute_cmd.assert_has_calls(calls['execute'])
