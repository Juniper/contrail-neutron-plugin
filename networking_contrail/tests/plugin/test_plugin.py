# Copyright 2019 Juniper Networks.  All rights reserved.

import datetime
import unittest
import uuid

import mock
from neutron_lib.exceptions import OverQuota
from oslo_config import cfg

from networking_contrail.plugin.plugin import ContrailPlugin


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
    auth_protocol = 'http'
    auth_host = 'host'
    auth_port = 5000
    admin_user = 'neutron'
    auth_url = "http://localhost:5000/"
    auth_type = ""
    admin_password = 'neutron'
    admin_token = 'neutron'
    admin_tenant_name = 'neutron'
    insecure = True
    certfile = "fake_cert.pem"
    keyfile = "fake_key.pem"
    cafile = "fake_ca.pem"
    auth_uri = "/v3"
    auth_version = "v3"


class ContrailPluginV2Test(unittest.TestCase):
    def setUp(self):
        cfg.CONF.keystone_authtoken = KeyStoneInfo()
        self.plugin = ContrailPlugin()

    def test_over_quota_raised_on_resource_creation_failure(self):
        resource_type = "network"
        context = Context(tenant_id='e17301da-7a64-4210-c77e-9fb9738674a9')
        res_data = {'network': {'name': 'fake_network',
                                'admin_state_up': True,
                                'tenant_id': context.tenant}}
        status_code = 400
        response_info = {
            u'msg': u'quota limit (3) exceeded for resource virtual_network',
            u'exception': u'OverQuota',
            u'overs': [u'virtual_network'],
        }

        over_quota_error = (status_code, response_info)

        with mock.patch.object(ContrailPlugin, '_request_backend',
                               return_value=over_quota_error),\
                self.assertRaises(OverQuota):
            self.plugin._create_resource(resource_type, context, res_data)
