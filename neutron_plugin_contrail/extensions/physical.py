# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
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


try:
    from neutron.api.extensions import ExtensionDescriptor
except ImportError:
    from neutron_lib.api.extensions import ExtensionDescriptor

try:
    from neutron.common.config import cfg
except ImportError:
    try:
        from oslo.config import cfg
    except ImportError:
        from oslo_config import cfg

import requests
import time

from vnc_api import vnc_api

vnc_conn = None


class Physical(ExtensionDescriptor):
    @classmethod
    def get_name(cls):
        return "physical"

    @classmethod
    def get_alias(cls):
        return "physical"

    @classmethod
    def get_description(cls):
        return "physical extension."

    @classmethod
    def get_namespace(cls):
        return "physical namespace"

    @classmethod
    def get_updated(cls):
        return "2017-03-13T10:00:00-00:00"

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
                time.sleep(3)

    def get_physical_router(self, fq_name):
        try:
            return self._get_vnc_conn().physical_router_read(fq_name=fq_name)
        except vnc_api.NoIdError:
            return None

    def get_physical_interface(self, fq_name):
        try:
            return self._get_vnc_conn().physical_interface_read(
                fq_name=fq_name)
        except vnc_api.NoIdError:
            return None

    def get_logical_interface(self, fq_name):
        try:
            return self._get_vnc_conn().logical_interface_read(fq_name=fq_name)
        except vnc_api.NoIdError:
            return None

    def get_virtual_machine_interface(self, uuid):
        try:
            return self._get_vnc_conn().virtual_machine_interface_read(id=uuid)
        except vnc_api.NoIdError:
            return None

    def create_physical_interface(self, fq_name):
        iface = vnc_api.PhysicalInterface(parent_type='physical-router',
                                          fq_name=fq_name)
        return self._get_vnc_conn().physical_interface_create(iface)

    def create_logical_interface(self, fq_name):
        iface = vnc_api.LogicalInterface(parent_type='physical-interface',
                                         fq_name=fq_name)
        iface_uuid = self._get_vnc_conn().logical_interface_create(iface)
        return self._get_vnc_conn().logical_interface_read(id=iface_uuid)

    def update_logical_interface(self, iface):
        return self._get_vnc_conn().logical_interface_update(iface)
