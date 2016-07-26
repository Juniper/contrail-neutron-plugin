# Derived from nova/virt/libvirt/vif.py
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

import socket

from os_vif import objects
from os_vif import plugin

from oslo_config import cfg
from oslo_concurrency import processutils
from oslo_log import log as logging

from vif_plug_vrouter import exception
from vif_plug_vrouter.i18n import _LE
from vif_plug_vrouter import privsep

LOG = logging.getLogger(__name__)
cfg.CONF.import_opt('virt_type', 'libvirt')

class VrouterPlugin(plugin.PluginBase):
    """A vRouter plugin that can setup VIFs in both kernel and vhostuser mode.

    TODO: Add more detailed description.
    """

    def describe(self):
        return objects.host_info.HostPluginInfo(
            plugin_name="ovs",
            vif_info=[
                objects.host_info.HostVIFInfo(
                    vif_object_name=objects.vif.VIFVHostUser.__name__,
                    min_version="1.0",
                    max_version="1.0")
            ])

    @staticmethod
    def _ip_version(address):
        # First try IPv4
        try:
            socket.inet_pton(socket.AF_INET, address)
            return 4
        except socket.error:
            pass

        # Then try IPv6
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return 6
        except socket.error:
            pass

        return False

    @staticmethod
    @privsep.vif_plug.entrypoint
    def _vrouter_port_add(instance_info, vif):
        ip_addr = '0.0.0.0'
        ip6_addr = None
        subnets = vif.network.subnets
        for subnet in subnets:
            if not hasattr(subnet, 'ips'):
                continue
            ip = subnet.ips[0]
            if not ip.address:
                continue

            if (self._ip_version(ip.address) == 4):
                if ip.address is not None:
                    ip_addr = ip.address
            if (self._ip_version(ip.address) == 6):
                if ip.address is not None:
                    ip6_addr = ip.address

        ptype = 'NovaVMPort'
        if (cfg.CONF.libvirt.virt_type == 'lxc'):
            ptype = 'NameSpacePort'

        vif_type = 'Vrouter'
        vhostuser_socket = ''
        if isinstance(vif, objects.vif.VIFVHostUser):
            vif_type = 'VhostUser'
            vhostuser_socket = ' --vhostuser_socket=%s' % vif.path

        cmd_args = ("--oper=add --uuid=%s --instance_uuid=%s --vn_uuid=%s "
                    "--vm_project_uuid=%s --ip_address=%s --ipv6_address=%s"
                    " --vm_name=%s --mac=%s --tap_name=%s --port_type=%s "
                    "--vif_type=%s%s --tx_vlan_id=%d --rx_vlan_id=%d" %
                    (vif.id, instance_info.uuid, vif.network.id,
                    instance_info.project_id, ip_addr, ip6_addr,
                    instance_info.name, vif.address,
                    vif.vif_name, ptype, vif_type, vhostuser_socket, -1, -1))

        try:
            processutils.execute('vrouter-port-control', cmd_args)
        except processutils.ProcessExecutionError as e:
            raise exception.VrouterPortControlError(cmd=cmd_args)

    def plug(self, vif, instance_info):
        if not isinstance(vif, objects.vif.VIFVHostUser):
            LOG.error(_LE("Unknown vif object type"))
            return
        # TODO: add check for VIFVRouter when support for kernel vRouter is
        # ready

        try:
            self._vrouter_port_add(instance_info, vif)
        except processutils.ProcessExecutionError:
            LOG.error(_LE("Failed while plugging vif"), instance=instance_info)

    @staticmethod
    @privsep.vif_plug.entrypoint
    def _vrouter_port_delete(instance_info, vif):
        cmd_args = ("--oper=delete --uuid=%s" % (vif.id))
        try:
            processutils.execute('vrouter-port-control', cmd_args)
        except processutils.ProcessExecutionError as e:
            raise exception.VrouterPortControlError(cmd=cmd_args)

    def unplug(self, vif, instance_info):
        if not isinstance(vif, objects.vif.VIFVHostUser):
            LOG.error(_LE("Unknown vif object type"))
            return
        # TODO: add check for VIFVRouter when support for kernel vRouter is
        # ready

        try:
            self._vrouter_port_delete(instance_info, vif)
        except processutils.ProcessExecutionError:
            LOG.error(_LE("Failed while unplugging vif"),
                    instance=instance_info)
