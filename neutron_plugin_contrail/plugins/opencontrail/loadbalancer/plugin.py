#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from loadbalancer_db import LoadBalancerPluginDb


class LoadBalancerPlugin(LoadBalancerPluginDb):
    supported_extension_aliases = ["lbaas"]

    def __init__(self):
        super(LoadBalancerPlugin, self).__init__()

    def get_plugin_description(self):
        return "OpenContrail LoadBalancer Service Plugin"

    def _pool_update_provider(self, context, pool):
        if 'provider' not in pool or not pool['provider'] or pool['provider'].__class__ is object:
            pool['provider'] = "opencontrail"

    def create_pool(self, context, pool):
        self._pool_update_provider(context, pool['pool'])
        return super(LoadBalancerPlugin, self).create_pool(context, pool)
