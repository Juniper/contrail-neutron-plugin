#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import requests
import time
import uuid

try:
    from neutron.common.config import cfg
except ImportError:
    try:
        from oslo.config import cfg
    except ImportError:
        from oslo_config import cfg

from cfgm_common import analytics_client
from cfgm_common import exceptions as vnc_exc
try:
    from neutron.common.exceptions import BadRequest
except ImportError:
    from neutron_lib.exceptions import BadRequest
try:
    from neutron.common.exceptions import NotAuthorized
except ImportError:
    from neutron_lib.exceptions import NotAuthorized

try:
    from neutron.extensions import loadbalancer
except ImportError:
    from neutron_lbaas.extensions import loadbalancer

try:
    from neutron.extensions.loadbalancer import LoadBalancerPluginBase
except ImportError:
    from neutron_lbaas.extensions.loadbalancer import LoadBalancerPluginBase

from vnc_api.vnc_api import VncApi

import loadbalancer_healthmonitor
import loadbalancer_member
import loadbalancer_pool
import virtual_ip


class LoadBalancerPluginDb(LoadBalancerPluginBase):

    def __init__(self):
        self.admin_user = cfg.CONF.keystone_authtoken.admin_user
        self.admin_password = cfg.CONF.keystone_authtoken.admin_password
        self.admin_tenant_name = cfg.CONF.keystone_authtoken.admin_tenant_name
        self.api_srvr_ip = cfg.CONF.APISERVER.api_server_ip
        self.api_srvr_port = cfg.CONF.APISERVER.api_server_port
        self.api_srvr_use_ssl= cfg.CONF.APISERVER.use_ssl
        try:
            self.auth_host = cfg.CONF.keystone_authtoken.auth_host
        except cfg.NoSuchOptError:
            self.auth_host = "127.0.0.1"

        try:
            self.auth_protocol = cfg.CONF.keystone_authtoken.auth_protocol
        except cfg.NoSuchOptError:
            self.auth_protocol = "http"

        try:
            self.auth_port = cfg.CONF.keystone_authtoken.auth_port
        except cfg.NoSuchOptError:
            self.auth_port = "35357"

        try:
            self.auth_url = cfg.CONF.keystone_authtoken.auth_url
        except cfg.NoSuchOptError:
            self.auth_url = "/v2.0/tokens"

        try:
            self.auth_type = cfg.CONF.auth_strategy
        except cfg.NoSuchOptError:
            self.auth_type = "keystone"

        try:
            self.api_server_url = cfg.CONF.APISERVER.api_server_url
        except cfg.NoSuchOptError:
            self.api_server_url = "/"

        try:
            self.auth_token_url= cfg.CONF.APISERVER.auth_token_url
        except cfg.NoSuchOptError:
            self.auth_token_url = None

    @property
    def api(self):
        if hasattr(self, '_api'):
            return self._api

        # Retry till a api-server is up
        connected = False
        while not connected:
            try:
                self._api = VncApi(self.admin_user, self.admin_password,
                        self.admin_tenant_name, self.api_srvr_ip,
                        self.api_srvr_port, self.api_server_url,
                        auth_host=self.auth_host, auth_port=self.auth_port,
                        auth_protocol=self.auth_protocol,
                        auth_url=self.auth_url, auth_type=self.auth_type,
                        wait_for_connect=True,
                        api_server_use_ssl=self.api_srvr_use_ssl,
                        auth_token_url=self.auth_token_url)
                connected = True
            except requests.exceptions.RequestException:
                time.sleep(3)
        return self._api

    @property
    def pool_manager(self):
        if hasattr(self, '_pool_manager'):
            return self._pool_manager

        self._pool_manager = \
            loadbalancer_pool.LoadbalancerPoolManager(self.api)

        return self._pool_manager

    @property
    def vip_manager(self):
        if hasattr(self, '_vip_manager'):
            return self._vip_manager

        self._vip_manager = virtual_ip.VirtualIpManager(self.api)

        return self._vip_manager

    @property
    def member_manager(self):
        if hasattr(self, '_member_manager'):
            return self._member_manager

        self._member_manager = \
            loadbalancer_member.LoadbalancerMemberManager(self.api)

        return self._member_manager

    @property
    def monitor_manager(self):
        if hasattr(self, '_monitor_manager'):
            return self._monitor_manager

        self._monitor_manager = \
            loadbalancer_healthmonitor.LoadbalancerHealthmonitorManager(
                self.api)

        return self._monitor_manager

    def get_api_client(self):
        return self.api

    def get_vips(self, context, filters=None, fields=None):
        return self.vip_manager.get_collection(context, filters, fields)

    def get_vip(self, context, id, fields=None):
        return self.vip_manager.get_resource(context, id, fields)

    def create_vip(self, context, vip):
        try:
            return self.vip_manager.create(context, vip)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='vip', msg=str(ex))

    def update_vip(self, context, id, vip):
        return self.vip_manager.update(context, id, vip)

    def delete_vip(self, context, id):
        return self.vip_manager.delete(context, id)

    def get_pools(self, context, filters=None, fields=None):
        return self.pool_manager.get_collection(context, filters, fields)

    def get_pool(self, context, id, fields=None):
        return self.pool_manager.get_resource(context, id, fields)

    def create_pool(self, context, pool):
        try:
            return self.pool_manager.create(context, pool)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='pool', msg=str(ex))

    def update_pool(self, context, id, pool):
        return self.pool_manager.update(context, id, pool)

    def delete_pool(self, context, id):
        return self.pool_manager.delete(context, id)

    def stats(self, context, pool_id):
        stats = {
            'bytes_in': '0',
            'bytes_out': '0',
            'active_connections': '0',
            'total_connections': '0',
        }

        endpoint = "http://%s:%s" % (cfg.CONF.COLLECTOR.analytics_api_ip,
                                     cfg.CONF.COLLECTOR.analytics_api_port)
        analytics = analytics_client.Client(endpoint)
        path = "/analytics/uves/service-instance/"
        fqdn_uuid = "%s?cfilt=UveLoadbalancer" % pool_id
        try:
            lb_stats = analytics.request(path, fqdn_uuid)
            pool_stats = lb_stats['UveLoadbalancer']['pool_stats']
        except Exception:
            pool_stats = []

        for pool_stat in pool_stats:
            stats['bytes_in'] = str(int(stats['bytes_in']) + int(pool_stat['bytes_in']))
            stats['bytes_out'] = str(int(stats['bytes_out']) + int(pool_stat['bytes_out']))
            stats['active_connections'] = str(int(stats['active_connections']) + int(pool_stat['current_sessions']))
            stats['total_connections'] = str(int(stats['total_connections']) + int(pool_stat['total_sessions']))
        return {'stats': stats}

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        """ Associate an health monitor with a pool.
        """
        m = health_monitor['health_monitor']
        try:
            pool = self.api.loadbalancer_pool_read(id=pool_id)
        except vnc_exc.NoIdError:
            raise loadbalancer.PoolNotFound(pool_id=pool_id)

        try:
            monitor = self.api.loadbalancer_healthmonitor_read(id=m['id'])
        except vnc_exc.NoIdError:
            raise loadbalancer.HealthMonitorNotFound(monitor_id=m['id'])

        if not context.is_admin:
            tenant_id = str(uuid.UUID(context.tenant_id))
            if tenant_id != pool.parent_uuid or \
                    tenant_id != monitor.parent_uuid:
                raise NotAuthorized()

        pool_refs = monitor.get_loadbalancer_pool_back_refs()
        if pool_refs is not None:
            for ref in pool_refs:
                if ref['uuid'] == pool_id:
                    raise loadbalancer.PoolMonitorAssociationExists(
                        monitor_id=m['id'], pool_id=pool_id)

        pool.add_loadbalancer_healthmonitor(monitor)
        self.api.loadbalancer_pool_update(pool)

        res = {
            'id': monitor.uuid,
            'tenant_id': monitor.parent_uuid.replace('-', '')
        }
        return res

    def get_pool_health_monitor(self, context, id, pool_id, fields=None):
        """ Query a specific pool, health_monitor association.
        """
        try:
            pool = self.api.loadbalancer_pool_read(id=pool_id)
        except vnc_exc.NoIdError:
            raise loadbalancer.PoolNotFound(pool_id=id)
        tenant_id = str(uuid.UUID(context.tenant_id))
        if not context.is_admin and tenant_id != pool.parent_uuid:
            raise loadbalancer.PoolNotFound(pool_id=id)

        in_list = False
        for mref in pool.get_loadbalancer_healthmonitor_refs() or []:
            if mref['uuid'] == id:
                in_list = True
                break

        if not in_list:
            raise loadbalancer.PoolMonitorAssociationNotFound(
                monitor_id=id, pool_id=pool_id)

        res = {
            'pool_id': pool_id,
            'monitor_id': id,
            'status': self.pool_manager._get_object_status(pool),
            'tenant_id': pool.parent_uuid.replace('-', '')
        }
        return self.pool_manager._fields(res, fields)

    def delete_pool_health_monitor(self, context, id, pool_id):
        try:
            pool = self.api.loadbalancer_pool_read(id=pool_id)
        except vnc_exc.NoIdError:
            raise loadbalancer.PoolNotFound(pool_id=id)
        tenant_id = str(uuid.UUID(context.tenant_id))
        if not context.is_admin and tenant_id != pool.parent_uuid:
            raise loadbalancer.PoolNotFound(pool_id=id)

        try:
            monitor = self.api.loadbalancer_healthmonitor_read(id=id)
        except vnc_exc.NoIdError:
            raise loadbalancer.HealthMonitorNotFound(monitor_id=id)

        in_list = False
        for mref in pool.get_loadbalancer_healthmonitor_refs():
            if mref['uuid'] == id:
                in_list = True
                break

        if not in_list:
            raise loadbalancer.PoolMonitorAssociationNotFound(
                monitor_id=id, pool_id=pool_id)

        pool.del_loadbalancer_healthmonitor(monitor)
        self.api.loadbalancer_pool_update(pool)

    def get_members(self, context, filters=None, fields=None):
        return self.member_manager.get_collection(context, filters, fields)

    def get_member(self, context, id, fields=None):
        return self.member_manager.get_resource(context, id, fields)

    def create_member(self, context, member):
        try:
            return self.member_manager.create(context, member)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='member', msg=str(ex))

    def update_member(self, context, id, member):
        return self.member_manager.update(context, id, member)

    def delete_member(self, context, id):
        return self.member_manager.delete(context, id)

    def get_health_monitors(self, context, filters=None, fields=None):
        return self.monitor_manager.get_collection(context, filters, fields)

    def get_health_monitor(self, context, id, fields=None):
        return self.monitor_manager.get_resource(context, id, fields)

    def create_health_monitor(self, context, health_monitor):
        try:
            return self.monitor_manager.create(context, health_monitor)
        except vnc_exc.PermissionDenied as ex:
            raise BadRequest(resource='health_monitor', msg=str(ex))

    def update_health_monitor(self, context, id, health_monitor):
        return self.monitor_manager.update(context, id, health_monitor)

    def delete_health_monitor(self, context, id):
        return self.monitor_manager.delete(context, id)
