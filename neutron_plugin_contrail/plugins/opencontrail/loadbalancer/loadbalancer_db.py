#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

from neutron.extensions.loadbalancer import LoadBalancerPluginBase
from vnc_api.vnc_api import VncApi

import loadbalancer_member
import loadbalancer_pool
import virtual_ip

class LoadBalancerPluginDb(LoadBalancerPluginBase):

    def __init__(self):
        # TODO: parse configuration for api-server:port and auth
        self._api = VncApi()
        self._pool_manager = \
            loadbalancer_pool.LoadbalancerPoolManager(self._api)
        self._vip_manager = virtual_ip.VirtualIpManager(self._api)
        self._member_manager = \
            loadbalancer_member.LoadbalancerMemberManager(self._api)

    def get_vips(self, context, filters=None, fields=None):
        return self._vip_manager.get_collection(context, filters, fields)

    def get_vip(self, context, id, fields=None):
        return self._vip_manager.get_resource(context, id, fields)

    def create_vip(self, context, vip):
        return self._vip_manager.create(context, vip)

    def update_vip(self, context, id, vip):
        return self._vip_manager.update(context, id, vip)

    def delete_vip(self, context, id):
        # TODO: automatically delete virtual-machine-interface
        return self._vip_manager.delete(context, id)

    def get_pools(self, context, filters=None, fields=None):
        return self._pool_manager.get_collection(context, filters, fields)

    def get_pool(self, context, id, fields=None):
        return self._pool_manager.get_resource(context, id, fields)

    def create_pool(self, context, pool):
        return self._pool_manager.create(context, pool)

    def update_pool(self, context, id, pool):
        return self._pool_manager.update(context, id, pool)

    def delete_pool(self, context, id):
        return self._pool_manager.delete(context, id)

    def stats(self, context, pool_id):
        pass

    def create_pool_health_monitor(self, context, health_monitor, pool_id):
        pass

    def get_pool_health_monitor(self, context, id, pool_id, fields=None):
        pass

    def delete_pool_health_monitor(self, context, id, pool_id):
        pass

    def get_members(self, context, filters=None, fields=None):
        return self._member_manager.get_collection(context, filters, fields)

    def get_member(self, context, id, fields=None):
        return self._member_manager.get_resource(context, id, fields)

    def create_member(self, context, member):
        return self._member_manager.create(context, member)

    def update_member(self, context, id, member):
        return self._member_manager.update(context, id, member)

    def delete_member(self, context, id):
        return self._member_manager.delete(context, id)

    def get_health_monitors(self, context, filters=None, fields=None):
        pass

    def get_health_monitor(self, context, id, fields=None):
        pass

    def create_health_monitor(self, context, health_monitor):
        pass

    def update_health_monitor(self, context, id, health_monitor):
        pass

    def delete_health_monitor(self, context, id):
        pass
