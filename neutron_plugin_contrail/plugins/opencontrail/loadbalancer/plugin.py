#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from loadbalancer_db import LoadBalancerPluginDb
from v2.loadbalancer_db import LoadBalancerPluginDbV2
try:
    from neutron.extensions import loadbalancer
except ImportError:
    from neutron_lbaas.extensions import loadbalancer


class LoadBalancerPlugin(LoadBalancerPluginDb):
    supported_extension_aliases = ["lbaas", "extra_lbaas_opts"]

    if hasattr(loadbalancer, 'LOADBALANCER_PREFIX'):
        path_prefix = loadbalancer.LOADBALANCER_PREFIX

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

class LoadBalancerPluginV2(LoadBalancerPluginDbV2):
    supported_extension_aliases = ["lbaasv2", "extra_lbaas_opts"]

    def __init__(self):
        super(LoadBalancerPluginV2, self).__init__()

    def get_plugin_description(self):
        return "OpenContrail LoadBalancerV2 Service Plugin"

    def _pool_update_provider(self, context, pool):
        if 'provider' not in pool or not pool['provider'] or pool['provider'].__class__ is object:
            pool['provider'] = "opencontrail"

    def create_pool(self, context, pool):
        self._pool_update_provider(context, pool['pool'])
        return super(LoadBalancerPluginV2, self).create_pool(context, pool)
