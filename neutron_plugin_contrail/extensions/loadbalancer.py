from neutron.api.v2 import attributes as attr
from neutron.api import extensions

# Extended_Attribute MAP
EXTENDED_ATTRIBUTES_2_0 = {
    'pools': {
        'custom_attributes': {'allow_post': True,
                              'allow_put': True,
                              'default': {},
                              'is_visible': True},
    }
}

class Loadbalancer(object):

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

#end class Loadbalancer
