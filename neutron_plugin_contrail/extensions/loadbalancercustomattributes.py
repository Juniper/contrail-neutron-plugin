from neutron.api.v2 import attributes as attr
from neutron.api import extensions

def _validate_custom_attributes(data, valid_values=None):
    if not isinstance(data, list):
        msg = _("Invalid data format for custom_attributes: '%s'") % data
        return msg

def convert_none_to_empty_list(value):
    return [] if value is None else value

attr.validators['type:customattributes'] = _validate_custom_attributes

# Extended_Attribute MAP
EXTENDED_ATTRIBUTES_2_0 = {
    'pools': {
        'custom_attributes': {'allow_post': True, 'allow_put': True,
                              'convert_to': convert_none_to_empty_list,
                              'default': attr.ATTR_NOT_SPECIFIED,
                              'validate': {'type:customattributes': None},
                              'is_visible': True},
    }
}


class Loadbalancercustomattributes(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Loadbalancer as a Service"


    @classmethod
    def get_alias(cls):
        return "extra_lbaas_opts"

    @classmethod
    def get_description(cls):
        return "Custom LBaaS attributes"

    @classmethod
    def get_namespace(cls):
        return "http://docs.openstack.org/TODO"

    @classmethod
    def get_updated(cls):
        return "2015-07-17T15:00:00-00:00"

    @classmethod
    def get_extended_resources(self, version):
        """Returns Ext Resources"""
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

#end class Loadbalancercustomattributes
