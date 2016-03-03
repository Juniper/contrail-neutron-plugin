from neutron.api.v2 import attributes as attr

EXTENDED_ATTRIBUTES_2_0 = {
    'ports': {
        'binding:vf': {'allow_post': True,
                       'allow_put': True,
                       'convert_list_to':
                        attr.convert_kvp_list_to_dict,
                       'default': attr.ATTR_NOT_SPECIFIED,
                       'is_visible': True},
    },
}


class Vfbinding(object):

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
