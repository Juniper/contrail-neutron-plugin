# Copyright (c) 2017 Mirantis Inc.
# All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import requests
import time

from neutron_lib.api.definitions import portbindings
from vnc_api import vnc_api
try:
    from neutron.common.config import cfg
except ImportError:
    try:
        from oslo.config import cfg
    except ImportError:
        from oslo_config import cfg
try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

LOG = logging.getLogger(__name__)


vnc_conn = None


class BaremetalVIF(object):

    @classmethod
    def _get_vnc_conn(cls):
        global vnc_conn
        if vnc_conn:
            return vnc_conn
        # Retry till a api-server is up
        while True:
            try:
                vnc_conn = vnc_api.VncApi(
                    cfg.CONF.keystone_authtoken.admin_user,
                    cfg.CONF.keystone_authtoken.admin_password,
                    cfg.CONF.keystone_authtoken.admin_tenant_name,
                    cfg.CONF.APISERVER.api_server_ip,
                    cfg.CONF.APISERVER.api_server_port,
                    auth_host=cfg.CONF.keystone_authtoken.auth_host,
                    auth_port=cfg.CONF.keystone_authtoken.auth_port,
                    auth_protocol=cfg.CONF.keystone_authtoken.auth_protocol,
                    api_server_use_ssl=cfg.CONF.APISERVER.use_ssl)
                return vnc_conn
            except requests.exceptions.RequestException as e:
                LOG.warning("VNC API is not accessible due to: $s" % e)
                time.sleep(3)
    # end _get_vnc_conn

    def is_port_baremetal(self, port):
        """Return whether a port is baremteal.

        Ports supported by this driver have a VNIC type of 'baremetal'.

        :param port: The port to check
        :returns: Whether the port is supported.
        """

        vnic_type = port.get(portbindings.VNIC_TYPE)
        return vnic_type == portbindings.VNIC_BAREMETAL

    def should_bind_port(selt, port):
        """Return whether a port is bound by this driver.

        Ports bound when host_id is present.

        :param port: The port to check
        :returns: Whether the port should be bound on the ToR.
        """

        return bool(port.get(portbindings.HOST_ID))

    def get_physical_port_info(self, port):
        """Return physical port info.

        :param port: The port to check
        :returns: tuple with (router_fq_name, physical_interface_name,
                              logical_interface_fq_name)
        """
        lli = port.get('binding:profile',
                       {}).get('local_link_information', [{}])
        switch_name = lli[0].get('switch_info')
        port_name = lli[0].get('port_id')

        if switch_name and port_name:
            router_fq_name = ['default-global-system-config', switch_name]
            piface_fq_name = router_fq_name + [port_name]
            liface_fq_name = piface_fq_name + [port_name + '.0']
            return router_fq_name, piface_fq_name, liface_fq_name
        return None, None, None

    def bind_baremetal_port(self, port):
        LOG.debug("Binding the baremetal port %s" % port['id'])
        ppi = self.get_physical_port_info(port)
        router_fq_name, piface_fq_name, liface_fq_name = ppi
        vnc_conn = self._get_vnc_conn()

        if not (router_fq_name and piface_fq_name):
            return

        if not vnc_conn.physical_router_read(
                fq_name=router_fq_name):
            LOG.debug("Binding skipped: physical router is not "
                      "registered.")
            return
        self._get_or_create_physical_interface(piface_fq_name)
        liface = self._get_or_create_logical_interface(liface_fq_name)
        vmi = vnc_conn.virtual_machine_interface_read(
            id=port['id'])

        liface.set_logical_interface_vlan_tag(0)
        liface.set_virtual_machine_interface(vmi)
        vnc_conn.logical_interface_update(liface)

        LOG.info("Baremetal port %s has been successfully bound." % port['id'])

    def _get_or_create_physical_interface(self, piface_fq_name):
        piface = None
        try:
            piface = self._get_vnc_conn().physical_interface_read(
                fq_name=piface_fq_name)
        except vnc_api.NoIdError:
            pass

        if not piface:
            iface = vnc_api.PhysicalInterface(parent_type='physical-router',
                                              fq_name=piface_fq_name)
            piface = self._get_vnc_conn().physical_interface_create(iface)

    def _get_or_create_logical_interface(self, liface_fq_name):
        liface = None
        try:
            liface = self._get_vnc_conn().logical_interface_read(
                fq_name=liface_fq_name)
        except vnc_api.NoIdError:
            pass

        if not liface:
            iface = vnc_api.LogicalInterface(parent_type='physical-interface',
                                             fq_name=liface_fq_name)
            iface_uuid = self._get_vnc_conn().logical_interface_create(iface)
            liface = self._get_vnc_conn().logical_interface_read(id=iface_uuid)

        return liface

    def unbind_baremetal_port(self, port):
        vnc_conn = self._get_vnc_conn()
        vmi = vnc_conn.virtual_machine_interface_read(id=port['id'])
        for lri_back_ref in vmi.get_logical_interface_back_refs() or []:
            vnc_conn.logical_interface_delete(id=lri_back_ref['uuid'])
