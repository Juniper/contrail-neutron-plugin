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


# Policy Exceptions
class PolicyNotFound(NotFound):
    message = _("Policy %(id)s could not be found")

# Attribute Map
RESOURCE_ATTRIBUTE_MAP = {
    'policys': {
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
        'entries': {'allow_post': True, 'allow_put': True,
                    'is_visible': True, 'default': ''},
        'nets_using': {'allow_post': False, 'allow_put': False,
                       'is_visible': True, 'default': ''},
    },
}


class Policy(ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Network Policy"

    @classmethod
    def get_alias(cls):
        return "policy"

    @classmethod
    def get_description(cls):
        return ("Configuration object for Network Policies")

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
        plugin = manager.NeutronManager.get_plugin()
        for resource_name in ['policy']:
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

#end class Policy


class PolicyPluginBase(object):

    @abstractmethod
    def create_policy(self, context, policy):
        pass

    @abstractmethod
    def update_policy(self, context, id, policy):
        pass

    @abstractmethod
    def get_policy(self, context, id, fields=None):
        pass

    @abstractmethod
    def delete_policy(self, context, id):
        pass

    @abstractmethod
    def get_policys(self, context, filters=None, fields=None):
        pass
#end class PolicyPluginBase
