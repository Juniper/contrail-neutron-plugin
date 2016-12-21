# Copyright 2016 Juniper Networks.  All rights reserved.
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

try:
    from neutron.api.v2 import attributes as converters
    ATTR_NOT_SPECIFIED = converters.ATTR_NOT_SPECIFIED
except ImportError:
    from neutron_lib.api import converters
    from neutron_lib import constants
    ATTR_NOT_SPECIFIED = constants.ATTR_NOT_SPECIFIED
try:
    from neutron.api import extensions
except ImportError:
    from neutron_lib.api import extensions

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        'binding:vf': {'allow_post': True,
                       'allow_put': True,
                       'convert_list_to': converters.convert_kvp_list_to_dict,
                       'default': ATTR_NOT_SPECIFIED,
                       'is_visible': True},
    },
}


class Vfbinding(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "vf-binding"

    @classmethod
    def get_alias(cls):
        return "vf-binding"

    @classmethod
    def get_description(cls):
        return ("Bindings for Virtual Function")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/TODO"

    @classmethod
    def get_updated(cls):
        return "2014-08-12T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}
# end class Vfbinding
