from abc import abstractmethod

try:
    from neutron.api.v2.attributes import UUID_PATTERN
except:
    from neutron_lib.constants import UUID_PATTERN
from neutron.api.v2 import base
try:
    from neutron.common.exceptions import NotFound
except ImportError:
    from neutron_lib.exceptions import NotFound
try:
    from neutron.api.extensions import ExtensionDescriptor
except ImportError:
    from neutron_lib.api.extensions import ExtensionDescriptor
from neutron.api.extensions import ResourceExtension
from neutron import manager

try:
    from oslo.config import cfg
except ImportError:
    from oslo_config import cfg

# Ocata compatibility
_use_plugins_directory = False
try:
    from neutron_lib.plugins import directory
    _use_plugins_directory = True
except ImportError:
    pass

# Ipam Exceptions
class IpamNotFound(NotFound):
    message = _("IPAM %(id)s could not be found")

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'ipams': {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:regex': UUID_PATTERN},
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': False,
                 'is_visible': True, 'default': ''},
        'fq_name': {'allow_post': False, 'allow_put': False,
                    'is_visible': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
        'mgmt': {'allow_post': True, 'allow_put': True,
                 'is_visible': True, 'default': None},
        'nets_using': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': ''}
    },
}


class Ipam(ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Network IP Address Management"

    @classmethod
    def get_alias(cls):
        return "ipam"

    @classmethod
    def get_description(cls):
        return ("Configuration object for holding common to a set of"
                " IP address blocks")

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/TODO"

    @classmethod
    def get_updated(cls):
        return "2012-07-20T10:00:00-00:00"

    @classmethod
    def get_resources(cls):
        """ Returns Ext Resources """
        exts = []
        if _use_plugins_directory:
            plugin = directory.get_plugin()
        else:
            plugin = manager.NeutronManager.get_plugin()

        for resource_name in ['ipam']:
            collection_name = resource_name + "s"
            params = RESOURCE_ATTRIBUTE_MAP.get(collection_name, dict())

            member_actions = {}

            controller = base.create_resource(collection_name,
                                              resource_name,
                                              plugin, params,
                                              member_actions=member_actions)

            ex = ResourceExtension(collection_name, controller,
                                   member_actions=member_actions)
            exts.append(ex)

        return exts

# end class Ipam


class IpamPluginBase(object):

    @abstractmethod
    def create_ipam(self, context, ipam):
        pass

    @abstractmethod
    def update_ipam(self, context, id, ipam):
        pass

    @abstractmethod
    def get_ipam(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_ipam(self, context, id):
        pass

    @abstractmethod
    def get_ipams(self, context, filters=None, fields=None):
        pass
# end class IpamPluginBase
