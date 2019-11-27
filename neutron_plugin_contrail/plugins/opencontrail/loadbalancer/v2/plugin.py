#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from neutron_lbaas.extensions import loadbalancerv2
from neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2.loadbalancer_db import LoadBalancerPluginDbV2


class LoadBalancerPluginV2(LoadBalancerPluginDbV2):
    supported_extension_aliases = ["lbaasv2",
                                   "extra_lbaas_opts",
                                   "lb_network_vip",]

    if hasattr(loadbalancerv2, 'LOADBALANCERV2_PREFIX'):
        path_prefix = loadbalancerv2.LOADBALANCERV2_PREFIX

    def __init__(self):
        super(LoadBalancerPluginV2, self).__init__()

    def get_plugin_description(self):
        return "OpenContrail LoadBalancerV2 Service Plugin"
