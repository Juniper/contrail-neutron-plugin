#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import mock
import unittest
import uuid

from neutron.openstack.common import uuidutils

from vnc_api.vnc_api import InstanceIp
from vnc_api.vnc_api import LoadbalancerPool, LoadbalancerPoolType
from vnc_api.vnc_api import Project
from vnc_api.vnc_api import ServiceInstance, ServiceInstanceType
from vnc_api.vnc_api import ServiceTemplate
from vnc_api.vnc_api import VirtualIp, VirtualIpType
from vnc_api.vnc_api import VirtualMachineInterface
from vnc_api.vnc_api import VirtualNetwork
from vnc_api.vnc_api import NoIdError


import importlib
_MODULE_PATH = 'neutron_plugin_contrail.plugins.opencontrail.loadbalancer'
mod_driver = importlib.import_module('%s.driver' % _MODULE_PATH)
mod_plugin = importlib.import_module('%s.plugin' % _MODULE_PATH)

_uuid = uuidutils.generate_uuid


class LoadbalancerDriverTest(unittest.TestCase):

    def setUp(self):
        super(LoadbalancerDriverTest, self).setUp()
        self._patcher = mock.patch('vnc_api.vnc_api.VncApi', autospec=True)
        self.api_server = self._patcher.start()
        plugin = mock.Mock(mod_plugin.LoadBalancerPlugin, autospec=True)
        plugin.get_api_client.return_value = self.api_server
        self.driver = mod_driver.OpencontrailLoadbalancerDriver(plugin)

    def tearDown(self):
        self._patcher.stop()
        super(LoadbalancerDriverTest, self).tearDown()

    def test_create_pool(self):
        tenant_id = _uuid()
        pool_id = _uuid()
        vip_id = _uuid()
        subnet_id = _uuid()

        api = self.api_server

        project = Project(name='test')
        project.uuid = tenant_id
        template = ServiceTemplate('lb-test', project)
        template.uuid = _uuid()

        pool_attrs = LoadbalancerPoolType()
        pool_attrs.subnet_id = subnet_id
        pool = LoadbalancerPool(
            pool_id, project, loadbalancer_pool_properties=pool_attrs)
        pool.uuid = pool_id

        vip_attrs = VirtualIpType()
        vip_attrs.subnet_id = subnet_id
        vip_attrs.address = '127.0.0.1'
        vip = VirtualIp(vip_id, project, virtual_ip_properties=vip_attrs)
        vip.uuid = vip_id
        vip.set_loadbalancer_pool(pool)

        vnet = VirtualNetwork('test', project)
        vnet.uuid = _uuid()

        vmi = VirtualMachineInterface(vip_id, project)
        vmi.uuid = _uuid()
        vmi.set_virtual_network(vnet)
        iip = InstanceIp(vip_id, instance_ip_address='127.0.0.1')
        iip.uuid = _uuid()
        iip.set_virtual_machine_interface(vmi)

        iip_refs = [
            {'to': iip.get_fq_name(), 'uuid': iip.uuid}
        ]
        vmi.get_instance_ip_back_refs = mock.Mock()
        vmi.get_instance_ip_back_refs.return_value = iip_refs

        vip.set_virtual_machine_interface(vmi)

        api.virtual_service_template_read = template
        api.loadbalancer_pool_read.return_value = pool
        api.virtual_ip_read.return_value = vip
        api.kv_retrieve.return_value = '%s %s' % (vnet.uuid, subnet_id)
        api.virtual_machine_interface_read.return_value = vmi
        api.instance_ip_read.return_value = iip
        api.service_instance_read.side_effect = NoIdError('404')

        context = {}
        pool_data = {
            'id': pool_id,
            'vip_id': vip_id
        }
        self.driver.create_pool(context, pool_data)
        api.service_instance_create.assert_called_with(mock.ANY)
