# Copyright 2015 Semihalf
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cfgm_common import exceptions as vnc_exc
from vnc_api import vnc_api

import contrail_res_handler as res_handler
import vn_res_handler as vn_handler

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

LOG = logging.getLogger(__name__)

class VirtualRouterMixin(object):
    @staticmethod
    def _virtual_router_to_neutron(router_obj):
        # TODO(md): Only dpdk enabled flag supported currently. Add more.
        if hasattr(router_obj, 'get_virtual_router_dpdk_enabled'):
            dpdk_enabled = router_obj.get_virtual_router_dpdk_enabled()
        else:
            dpdk_enabled = False

        # The .get_<resource>() method of VirtualRouter object seems to return
        # None in case a boolean is not set. Therefore the 'or False'
        # expression below to assure True or False values
        vr = {'dpdk_enabled': dpdk_enabled or False}
        return vr

class VirtualRouterGetHandler(res_handler.ResourceGetHandler,
                              VirtualRouterMixin):
    resource_get_method = "virtual_router_read"
    resource_list_method = "virtual_routers_list"

    def resource_get(self, context, vrouter_id, fields=None):
        try:
            router_obj = self._resource_get(fq_name=vrouter_id)
        except vnc_exc.NoIdError:
            # TODO(md): Check the exception that has to be rised here
            self._raise_contrail_exception('VirtualRouterNotFound',
                                           id=vrouter_id,
                                           resource='virtual_router')

        return self._virtual_router_to_neutron(router_obj)

    def resource_list(self, context, filters=None, fields=None):
        router_obj = self._resource_list(filters=filters, fields=fields)
        return router_obj

class VirtualRouterHandler(VirtualRouterGetHandler):
    pass
