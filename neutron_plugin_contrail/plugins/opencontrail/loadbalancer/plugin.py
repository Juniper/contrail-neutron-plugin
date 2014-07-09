#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from loadbalancer_db import LoadBalancerPluginDb
import logging
LOG = logging.getLogger(__name__)

class LoadBalancerPlugin(LoadBalancerPluginDb):
    supported_extension_aliases = ["lbaas"]

    def get_plugin_description(self):
        return "OpenContrail LoadBalancer Service Plugin"


