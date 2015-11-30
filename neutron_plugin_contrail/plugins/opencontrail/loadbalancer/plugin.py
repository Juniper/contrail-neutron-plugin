#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from loadbalancer_db import LoadBalancerPluginDb

try:
    from neutron.extensions import loadbalancer
except ImportError:
    from neutron_lbaas.extensions import loadbalancer
from neutron.db import servicetype_db as sdb
from neutron.plugins.common import constants
from neutron.services import provider_configuration as pconf


class LoadBalancerPlugin(LoadBalancerPluginDb):
    supported_extension_aliases = ["lbaas", "extra_lbaas_opts"]

    if hasattr(loadbalancer, 'LOADBALANCER_PREFIX'):
        path_prefix = loadbalancer.LOADBALANCER_PREFIX

    def __init__(self):
        super(LoadBalancerPlugin, self).__init__()
        self._get_default_provider()

    def _get_default_provider(self):
        service_type_manager = sdb.ServiceTypeManager.get_instance()
        try:
            provider = (service_type_manager.
                        get_default_service_provider(None,
                                                     constants.LOADBALANCER))
        except pconf.DefaultServiceProviderNotFound:
            self.default_provider = "opencontrail"
        else:
            self._pool_manager.check_provider_exists(provider['name'])
            self.default_provider = provider['name']

    def get_plugin_description(self):
        return "OpenContrail LoadBalancer Service Plugin"

    def _pool_update_provider(self, context, pool):
        if 'provider' not in pool or not pool['provider'] or pool['provider'].__class__ is object:
            pool['provider'] = self.default_provider

    def create_pool(self, context, pool):
        self._pool_update_provider(context, pool['pool'])
        return super(LoadBalancerPlugin, self).create_pool(context, pool)
