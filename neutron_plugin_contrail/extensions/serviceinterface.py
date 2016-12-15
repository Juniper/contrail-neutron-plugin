#from neutron.api.v2 import attributes as attr
try:
    from neutron_lib import constants
except ImportError:
    from neutron.api.v2 import attributes as constants
try:
    from neutron_lib.api import extensions
except ImportError:
    from neutron.api import extensions

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        'binding:service_interface_type': {'allow_post': True,
                             'allow_put': False,
                             'default': constants.ATTR_NOT_SPECIFIED,
                             'is_visible': True},
    },
}


class Serviceinterface(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "service-interface"

    @classmethod
    def get_alias(cls):
        return "service-interface"

    @classmethod
    def get_description(cls):
        return ("Service Interface")

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
# end class ServiceInterface
