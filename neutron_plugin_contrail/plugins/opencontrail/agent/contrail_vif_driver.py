#
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

import ConfigParser
import time
import uuid

from neutron.agent.linux import interface
from neutron.agent.linux import ip_lib

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

from neutron.openstack.common import loopingcall

from contrail_vrouter_api.vrouter_api import ContrailVRouterApi
from vnc_api.vnc_api import *

from neutron_plugin_contrail.common import utils

LOG = logging.getLogger(__name__)


class ContrailInterfaceDriver(interface.LinuxInterfaceDriver):
    """ Opencontrail VIF driver for neutron."""

    def __init__(self, conf):
        super(ContrailInterfaceDriver, self).__init__(conf)
        self._port_dict = {}
        self._client = utils.get_vnc_api_instance()
        self._vrouter_client = ContrailVRouterApi()
        timer = loopingcall.FixedIntervalLoopingCall(self._keep_alive)
        timer.start(interval=2)

    def _keep_alive(self):
        self._vrouter_client.periodic_connection_check()

    def _delete_port(self, port_id):
        self._vrouter_client.delete_port(port_id)

    def _instance_locate(self, port_obj):
        """ lookup the instance associated with the port object.
        Create the vm instance if port object is not associated
        with a vm instance
        """
        if port_obj.get_virtual_machine_refs() is not None:
            try:
                vm_uuid = port_obj.get_virtual_machine_refs()[0]['uuid']
                instance_obj = self._client.virtual_machine_read(id=vm_uuid)
                return instance_obj
            except NoIdError:
                pass

        vm_uuid = str(uuid.uuid4())
        instance_obj = VirtualMachine(vm_uuid)
        instance_obj.uuid = vm_uuid
        self._client.virtual_machine_create(instance_obj)
        port_obj.set_virtual_machine(instance_obj)
        self._client.virtual_machine_interface_update(port_obj)
        return instance_obj

    def _add_port_to_agent(self, port_id, net_id, iface_name, mac_address):
        port_obj = self._client.virtual_machine_interface_read(id=port_id)
        if port_obj is None:
            LOG.debug(_("Invalid port_id : %s"), port_id)
            return

        ips = port_obj.get_instance_ip_back_refs()
        ip_addr = '0.0.0.0'
        # get the ip address of the port if associated
        if ips and len(ips):
            ip_uuid = ips[0]['uuid']
            ip = self._client.instance_ip_read(id=ip_uuid)
            ip_addr = ip.get_instance_ip_address()

        net_obj = self._client.virtual_network_read(id=net_id)
        if net_obj is None:
            LOG.debug(_("Invalid net_id : %s"), net_id)
            return

        # get the instance object the port is attached to
        instance_obj = self._instance_locate(port_obj)

        if instance_obj is None:
            return

        kwargs = {}
        kwargs['ip_address'] = ip_addr
        kwargs['network_uuid'] = net_id
        kwargs['vm_project_uuid'] = net_obj.parent_uuid
        self._vrouter_client.add_port(instance_obj.uuid, port_id, iface_name,
                                      mac_address, **kwargs)

    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        if not ip_lib.device_exists(device_name, self.root_helper, namespace):
            ip = ip_lib.IPWrapper(self.root_helper)
            tap_name = device_name.replace(prefix or 'veth', 'veth')

            # Create ns_dev in a namespace if one is configured.
            root_dev, ns_dev = ip.add_veth(tap_name,
                                           device_name,
                                           namespace2=namespace)
            ns_dev.link.set_address(mac_address)
            namespace_obj = ip.ensure_namespace(namespace)
            namespace_obj.add_device_to_namespace(ns_dev)
            ns_dev.link.set_up()
            root_dev.link.set_up()

            self._add_port_to_agent(port_id, network_id,
                                    tap_name, mac_address)
            self._port_dict[tap_name] = port_id
        else:
            LOG.warn(_("Device %s already exists"), device_name)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        tap_name = device_name.replace(prefix or 'veth', 'veth')
        if tap_name in self._port_dict:
            self._delete_port(self._port_dict[tap_name])
            del self._port_dict[tap_name]

        device = ip_lib.IPDevice(device_name, self.root_helper, namespace)
        device.link.delete()
        LOG.debug(_("Unplugged interface '%s'"), device_name)
        ip_lib.IPWrapper(
            self.root_helper, namespace).garbage_collect_namespace()
