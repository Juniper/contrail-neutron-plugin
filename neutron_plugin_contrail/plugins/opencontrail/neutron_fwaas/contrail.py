# Copyright 2018 Juniper Networks. All rights reserved.
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
#

from oslo_log import log as logging

from neutron_fwaas.services.firewall.service_drivers.driver_api import \
    FirewallDriver
from neutron_lib.api.definitions import portbindings as pb_def


LOG = logging.getLogger(__name__)


class ContrailFirewallv2Driver(FirewallDriver):
    """Contrail Neutron Firewall v2 driver"""

    def is_supported_l2_port(self, port):
        if port[pb_def.VIF_TYPE] == 'vrouter':
            return True
        return False

    def is_supported_l3_port(self, port):
        return False

    # Firewall Group
    def create_firewall_group(self, context, firewall_group):
        return self._core_plugin._create_resource(
            'firewall_group', context, {'firewall_group': firewall_group})

    def delete_firewall_group(self, context, id):
        self._core_plugin._delete_resource('firewall_group', context, id)

    def get_firewall_group(self, context, id, fields=None):
        return self._core_plugin._get_resource(
            'firewall_group', context, id, fields)

    def get_firewall_groups(self, context, filters=None, fields=None):
        return self._core_plugin._list_resource(
            'firewall_group', context, filters, fields)

    def update_firewall_group(self, context, id, firewall_group):
        return self._core_plugin._update_resource(
            'firewall_group', context, id, {'firewall_group': firewall_group})

    # Firewall Policy
    def create_firewall_policy(self, context, firewall_policy):
        return self._core_plugin._create_resource(
            'firewall_policy', context, {'firewall_policy': firewall_policy})

    def delete_firewall_policy(self, context, id):
        self._core_plugin._delete_resource('firewall_policy', context, id)

    def get_firewall_policy(self, context, id, fields=None):
        return self._core_plugin._get_resource(
            'firewall_policy', context, id, fields)

    def get_firewall_policies(self, context, filters=None, fields=None):
        return self._core_plugin._list_resource(
            'firewall_policy', context, filters, fields)

    def update_firewall_policy(self, context, id, firewall_policy):
        return self._core_plugin._update_resource(
            'firewall_policy',
            context,
            id,
            {'firewall_policy': firewall_policy})

    def insert_rule(self, context, policy_id, rule_info):
        self._insert_or_remove_rule(context, 'INSERT_RULE', policy_id,
                                    rule_info)

    def remove_rule(self, context, policy_id, rule_info):
        self._insert_or_remove_rule(context, 'REMOVE_RULE', policy_id,
                                    rule_info)

    def _insert_or_remove_rule(self, context, action, policy_id, rule_info):
        res_dict = self._core_plugin._encode_resource(resource_id=policy_id,
                                                      resource=rule_info)
        status_code, res_info = self._core_plugin._request_backend(
            context, res_dict, 'firewall_policy', action)
        res_dicts = self._core_plugin._transform_response(
            status_code, info=res_info, obj_name='firewall_policy')
        LOG.debug("Firewall Policy %(action)s(): policy_id: %(policy_id)s "
                  "rule_info: %(rule_info)r",
                  {'action': action.lower(), 'policy_id': policy_id,
                   'rule_info': rule_info})

        return res_dicts

    # Firewall Rule
    def create_firewall_rule(self, context, firewall_rule):
        return self._core_plugin._create_resource(
            'firewall_rule', context, {'firewall_rule': firewall_rule})

    def delete_firewall_rule(self, context, id):
        self._core_plugin._delete_resource('firewall_rule', context, id)

    def get_firewall_rule(self, context, id, fields=None):
        return self._core_plugin._get_resource(
            'firewall_rule', context, id, fields)

    def get_firewall_rules(self, context, filters=None, fields=None):
        return self._core_plugin._list_resource(
            'firewall_rule', context, filters, fields)

    def update_firewall_rule(self, context, id, firewall_rule):
        return self._core_plugin._update_resource(
            'firewall_rule', context, id, {'firewall_rule': firewall_rule})
