# Copyright 2018 Juniper Networks.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging

from neutron_lib.services import base as service_base
from neutron_lib.api.definitions import trunk as trunk_apidef
from neutron_lib.api.definitions import trunk_details
from neutron_lib.plugins import directory

LOG = logging.getLogger(__name__)

class TrunkPlugin(service_base.ServicePluginBase):
    """Implements Contrail Neutron Trunk Service plugin."""

    supported_extension_aliases = [trunk_apidef.ALIAS]

    def __init__(self):
        super(TrunkPlugin, self).__init__()

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    @classmethod
    def get_plugin_type(cls):
        return 'trunk'

    def get_plugin_description(self):
        return 'Trunk port service plugin'

    def create_trunk(self, context, trunk):
        return self._core_plugin._create_resource(
            'trunk', context, trunk)

    def get_trunk(self, context, id, fields=None):
        """Return information for the specified trunk."""
        return self._core_plugin._get_resource(
            'trunk', context, id, fields)

    def get_trunks(self, context, filters=None, fields=None):
        return self._core_plugin._list_resource(
            'trunk', context, filters, fields)

    def get_subports(self, context, trunk_id, fields=None):
        """Return subports for the specified trunk."""
        trunk = self.get_trunk(context, trunk_id, fields=['sub_ports'])
        return {'sub_ports': trunk['sub_ports']}

    def update_trunk(self, context, id, trunk):
        return self._core_plugin._update_resource(
           'trunk',
           context,
           id,
           {'trunk': trunk})

    def delete_trunk(self, context, id):
        self._core_plugin._delete_resource('trunk', context, id)

    def add_subports(self, context, trunk_id, subports):
        self._add_or_remove_subports(context, 'ADD_SUBPORTS', trunk_id,
                                    subports)

    def remove_subports(self, context, trunk_id, subports):
        self._add_or_remove_subports(context, 'REMOVE_SUBPORTS', trunk_id,
                                    subports)

    def _add_or_remove_subports(self, context, action, trunk_id, subports):
        res_dict = self._core_plugin._encode_resource(resource_id=trunk_id,
                                                      resource=subports)
        status_code, res_info = self._core_plugin._request_backend(
            context, res_dict, 'trunk', action)
        res_dicts = self._core_plugin._transform_response(
            status_code, info=res_info, obj_name='trunk')
        LOG.debug("Trunk %(action)s(): trunk_id: %(trunk_id)s "
                  "subports: %(subports)r",
                  {'action': action.lower(), 'trunk_id': trunk_id,
                   'trunk': trunk_id})

        return res_dicts
