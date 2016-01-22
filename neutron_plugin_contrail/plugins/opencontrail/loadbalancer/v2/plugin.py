#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from neutron_lbaas.extensions import loadbalancerv2
from loadbalancer_db import LoadBalancerPluginDbV2


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
