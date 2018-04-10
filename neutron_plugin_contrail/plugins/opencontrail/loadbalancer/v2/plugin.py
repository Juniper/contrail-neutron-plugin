#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

# License: Apache-2.0
# Copyright (c) 2016 HUAWEI TECHNOLOGIES CO.,LTD and others.
# https://github.com/openstack/compass-adapters/blob/master/ansible/roles/open-contrail/templates/neutron_plugin_contrail.tar.gz

from neutron_lbaas.extensions import loadbalancerv2
from loadbalancer_db import LoadBalancerPluginDbV2


class LoadBalancerPluginV2(LoadBalancerPluginDbV2):
    supported_extension_aliases = ["lbaasv2", "extra_lbaas_opts"]

    if hasattr(loadbalancerv2, 'LOADBALANCERV2_PREFIX'):
        path_prefix = loadbalancerv2.LOADBALANCERV2_PREFIX

    def __init__(self):
        super(LoadBalancerPluginV2, self).__init__()

    def get_plugin_description(self):
        return "OpenContrail LoadBalancerV2 Service Plugin"
