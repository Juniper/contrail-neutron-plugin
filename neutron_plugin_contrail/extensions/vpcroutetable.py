# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 OpenStack Foundation.
# All rights reserved.
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

from abc import ABCMeta
from abc import abstractmethod

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

try:
    from neutron.api.extensions import ExtensionDescriptor
except ImportError:
    from neutron_lib.api.extensions import ExtensionDescriptor
from neutron.api.extensions import ResourceExtension
from neutron.api.v2 import base
try:
    from neutron.common.exceptions import NotFound
except ImportError:
    from neutron_lib.exceptions import NotFound
from neutron import manager
try:
    from neutron.quota import resource_registry as quota
except ImportError:
    from neutron.quota import QUOTAS as quota

try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils

# Ocata compatibility
_use_plugins_directory = False
try:
    from neutron_lib.plugins import directory
    _use_plugins_directory = True
except ImportError:
    pass

# Route table Exceptions
class RouteTableNotFound(NotFound):
    message = _("Route table %(id)s does not exist")

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'route_tables': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'fq_name': {'allow_post': True, 'allow_put': False,
                    'is_visible': True, 'default': '',
                    'validate': {'type:name_not_default': None}},
        'routes': {'allow_post': True, 'allow_put': True,
                   'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
    'nat_instances': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_visible': True,
               'primary_key': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': '',
                 'validate': {'type:name_not_default': None}},
        'fq_name': {'allow_post': True, 'allow_put': False,
                    'is_visible': True, 'default': '',
                    'validate': {'type:name_not_default': None}},
        'internal_net': {'allow_post': True, 'allow_put': False,
                         'is_visible': True, 'default': ''},
        'internal_ip': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': ''},
        'external_net': {'allow_post': True, 'allow_put': False,
                         'is_visible': True, 'default': ''},
        'external_ip': {'allow_post': True, 'allow_put': False,
                        'is_visible': True, 'default': ''},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    },
}

EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'vpc:route_table': {'allow_post': True,
                            'allow_put': True,
                            'default': '',
                            'is_visible': True},
    }
}


class Vpcroutetable(ExtensionDescriptor):
    """ Route table extension"""

    @classmethod
    def get_name(cls):
        return "route-table"

    @classmethod
    def get_alias(cls):
        return "route-table"

    @classmethod
    def get_description(cls):
        return "VPC route tables extension."

    @classmethod
    def get_namespace(cls):
        # todo
        return "http://docs.openstack.org/ext/routetables/api/v2.0"

    @classmethod
    def get_updated(cls):
        return "2013-07-24T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        if _use_plugins_directory:
            plugin = directory.get_plugin()
        else:
            plugin = manager.NeutronManager.get_plugin()

        for resource_name in ['route_table', 'nat_instance']:
            collection_name = resource_name.replace('_', '-') + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(resource_name + "s", dict())
            quota.register_resource_by_name(resource_name)
            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params, allow_bulk=True,
                                              allow_pagination=True,
                                              allow_sorting=True)

            ex = ResourceExtension(collection_name, controller,
                                   attr_map=params)
            exts.append(ex)

        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


class RouteTablePluginBase(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def create_route_table(self, context, route_table):
        pass

    @abstractmethod
    def delete_route_table(self, context, id):
        pass

    @abstractmethod
    def update_route_table(self, context, id, route_table):
        pass

    @abstractmethod
    def get_route_tables(self, context, filters=None, fields=None,
                         sorts=None, limit=None, marker=None,
                         page_reverse=False):
        pass

    @abstractmethod
    def get_route_table(self, context, id, fields=None):
        pass

    @abstractmethod
    def create_nat_instance(self, context, nat_instance):
        pass

    @abstractmethod
    def delete_nat_instance(self, context, id):
        pass

    @abstractmethod
    def get_nat_instances(self, context, filters=None, fields=None,
                          sorts=None, limit=None, marker=None,
                          page_reverse=False):
        pass

    @abstractmethod
    def get_nat_instance(self, context, id, fields=None):
        pass
