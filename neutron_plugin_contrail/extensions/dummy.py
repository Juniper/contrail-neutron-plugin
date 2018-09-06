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

import abc
import six

from neutron.api.v2 import resource_helper
from neutron_lib.api import extensions
from neutron_lib.services import base as service_base
from oslo_log import log as logging

from neutron_plugin_contrail.plugins.opencontrail.services.dummy import dummy_api_def


LOG = logging.getLogger(__name__)


class Dummy(extensions.APIExtensionDescriptor):
    """Extension class supporting dummy.

    Implements a Dummy Neutron service extension for test and demo.
    """

    api_definition = dummy_api_def

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, dummy_api_def.RESOURCE_ATTRIBUTE_MAP)
        return resource_helper.build_resource_info(
            plural_mappings,
            dummy_api_def.RESOURCE_ATTRIBUTE_MAP,
            dummy_api_def.ALIAS)

    @classmethod
    def get_plugin_interface(cls):
        return DummyServicePluginBase


@six.add_metaclass(abc.ABCMeta)
class DummyServicePluginBase(service_base.ServicePluginBase):
    """Implements Contrail Neutron Dummy Service plugin."""

    supported_extension_aliases = [dummy_api_def.ALIAS]

    @classmethod
    def get_plugin_type(cls):
        return dummy_api_def.ALIAS

    def get_plugin_description(self):
        return dummy_api_def.DESCRIPTION

    @abc.abstractmethod
    def create_dummy(self, context, dummy):
        pass

    @abc.abstractmethod
    def get_dummys(self, context, filters=None, fields=None,
                   sorts=None, limit=None, marker=None, page_reverse=False):
        pass

    @abc.abstractmethod
    def get_dummy(self, context, id, fields=None):
        pass

    @abc.abstractmethod
    def update_dummy(self, context, id, dummy):
        pass

    @abc.abstractmethod
    def delete_dummy(self, context, id):
        pass