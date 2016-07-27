#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import requests
import time
import uuid

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

from cfgm_common import analytics_client
from cfgm_common import exceptions as vnc_exc
from neutron.common import exceptions as n_exc

from neutron_lbaas.extensions import loadbalancerv2
from neutron_lbaas.extensions.loadbalancerv2 import LoadBalancerPluginBaseV2

from vnc_api.vnc_api import VncApi

import loadbalancer_healthmonitor
import loadbalancer_member
import loadbalancer_pool
import loadbalancer
import listener


class LoadBalancerPluginDbV2(LoadBalancerPluginBaseV2):

    def __init__(self):
        admin_user = cfg.CONF.keystone_authtoken.admin_user
        admin_password = cfg.CONF.keystone_authtoken.admin_password
        admin_tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
        api_srvr_ip = cfg.CONF.APISERVER.api_server_ip
        api_srvr_port = cfg.CONF.APISERVER.api_server_port
        try:
            auth_host = cfg.CONF.keystone_authtoken.auth_host
        except cfg.NoSuchOptError:
            auth_host = "127.0.0.1"

        try:
            auth_protocol = cfg.CONF.keystone_authtoken.auth_protocol
        except cfg.NoSuchOptError:
            auth_protocol = "http"

        try:
            auth_port = cfg.CONF.keystone_authtoken.auth_port
        except cfg.NoSuchOptError:
            auth_port = "35357"

        try:
            auth_url = cfg.CONF.keystone_authtoken.auth_url
        except cfg.NoSuchOptError:
            auth_url = "/v2.0/tokens"

        try:
            auth_type = cfg.CONF.keystone_authtoken.auth_type
        except cfg.NoSuchOptError:
            auth_type = "keystone"

        try:
            api_server_url = cfg.CONF.APISERVER.api_server_url
        except cfg.NoSuchOptError:
            api_server_url = "/"

    @property
    def api(self):
        if getattr(self, '_api'):
            return self._api

        # Retry till a api-server is up
        connected = False
        while not connected:
            try:
                self._api = VncApi(admin_user, admin_password, admin_tenant_name,
                                   api_srvr_ip, api_srvr_port, api_server_url,
                                   auth_host=auth_host, auth_port=auth_port,
                                   auth_protocol=auth_protocol, auth_url=auth_url,
                                   auth_type=auth_type, wait_for_connect=True)
                connected = True
            except requests.exceptions.RequestException:
                time.sleep(3)

    @property
    def pool_manager(self):
        if getattr(self, '_pool_manager'):
            return self._pool_manager

        self._pool_manager = \
            loadbalancer_pool.LoadbalancerPoolManager(self.api)

        return self._pool_manager

    @property
    def loadbalancer_manager(self):
        if getattr(self, '_loadbalancer_manager'):
            return self._loadbalancer_manager

        self._loadbalancer_manager = loadbalancer.LoadbalancerManager(self.api)

        return self._loadbalancer_manager

    @property
    def listener_manager(self):
        if getattr(self, '_listener_manager'):
            return self._listener_manager
        self._listener_manager = listener.ListenerManager(self.api)

        return self._listener_manager

    @property
    def member_manager(self):
        if getattr(self, '_member_manager'):
            return self._member_manager

        self._member_manager = \
            loadbalancer_member.LoadbalancerMemberManager(self.api)

        return self._member_manager

    @property
    def monitor_manager(self):
        if getattr(self, '_monitor_manager'):
            return self._monitor_manager
        self._monitor_manager = \
            loadbalancer_healthmonitor.LoadbalancerHealthmonitorManager(
                self.api)

        return self._monitor_manager

    def get_api_client(self):
        return self.api

    def get_loadbalancers(self, context, filters=None, fields=None):
        return self.loadbalancer_manager.get_collection(context, filters, fields)

    def get_loadbalancer(self, context, id, fields=None):
        return self.loadbalancer_manager.get_resource(context, id, fields)

    def create_loadbalancer(self, context, loadbalancer):
        try:
            return self.loadbalancer_manager.create(context, loadbalancer)
        except vnc_exc.PermissionDenied as ex:
            raise n_exc.BadRequest(resource='loadbalancer', msg=str(ex))

    def update_loadbalancer(self, context, id, loadbalancer):
        return self.loadbalancer_manager.update(context, id, loadbalancer)

    def delete_loadbalancer(self, context, id):
        return self.loadbalancer_manager.delete(context, id)

    def create_listener(self, context, listener):
        try:
            return self.listener_manager.create(context, listener)
        except vnc_exc.PermissionDenied as ex:
            raise n_exc.BadRequest(resource='listener', msg=str(ex))

    def get_listener(self, context, id, fields=None):
        return self.listener_manager.get_resource(context, id, fields)

    def get_listeners(self, context, filters=None, fields=None):
        return self.listener_manager.get_collection(context, filters, fields)

    def update_listener(self, context, id, listener):
        return self.listener_manager.update(context, id, listener)

    def delete_listener(self, context, id):
        return self.listener_manager.delete(context, id)

    def get_pools(self, context, filters=None, fields=None):
        return self.pool_manager.get_collection(context, filters, fields)

    def get_pool(self, context, id, fields=None):
        return self.pool_manager.get_resource(context, id, fields)

    def create_pool(self, context, pool):
        try:
            return self.pool_manager.create(context, pool)
        except vnc_exc.PermissionDenied as ex:
            raise n_exc.BadRequest(resource='pool', msg=str(ex))

    def update_pool(self, context, id, pool):
        return self.pool_manager.update(context, id, pool)

    def delete_pool(self, context, id):
        return self.pool_manager.delete(context, id)

    def get_pool_members(self, context, pool_id, filters=None, fields=None):
        return self.member_manager.get_collection(context, pool_id, filters, fields)

    def get_pool_member(self, context, id, pool_id, fields=None):
        return self.member_manager.get_resource(context, id, pool_id, fields)

    def create_pool_member(self, context, pool_id, member):
        try:
            return self.member_manager.create(context, pool_id, member)
        except vnc_exc.PermissionDenied as ex:
            raise n_exc.BadRequest(resource='member', msg=str(ex))

    def update_pool_member(self, context, id, pool_id, member):
        return self.member_manager.update(context, id, member)

    def delete_pool_member(self, context, id, pool_id):
        return self.member_manager.delete(context, id, pool_id)

    def get_members(self, context, filters=None, fields=None):
        pass

    def get_member(self, context, id, fields=None):
        pass

    def get_healthmonitors(self, context, filters=None, fields=None):
        return self.monitor_manager.get_collection(context, filters, fields)

    def get_healthmonitor(self, context, id, fields=None):
        return self.monitor_manager.get_resource(context, id, fields)

    def create_healthmonitor(self, context, healthmonitor):
        try:
            return self.monitor_manager.create(context, healthmonitor)
        except vnc_exc.PermissionDenied as ex:
            raise n_exc.BadRequest(resource='healthmonitor', msg=str(ex))

    def update_healthmonitor(self, context, id, healthmonitor):
        return self.monitor_manager.update(context, id, healthmonitor)

    def delete_healthmonitor(self, context, id):
        return self.monitor_manager.delete(context, id)

    def stats(self, context, loadbalancer_id):
        pass

    def statuses(self, context, loadbalancer_id):
        pass
