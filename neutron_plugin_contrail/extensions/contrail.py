from neutron.api import extensions


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'contrail:fq_name': {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
        'contrail:instance_count': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
        'contrail:policys': {'allow_post': True,
                             'allow_put': True,
                             'default': '',
                             'is_visible': True},
        'contrail:subnet_ipam': {'allow_post': False,
                                 'allow_put': False,
                                 'default': '',
                                 'is_visible': True},
    },
    'routers': {
        'contrail:fq_name': {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
    },
    'security_groups': {
        'contrail:fq_name': {'allow_post': False,
                             'allow_put': False,
                             'is_visible': True},
    },
    'subnets': {
        'contrail:instance_count': {'allow_post': False,
                                    'allow_put': False,
                                    'is_visible': True},
        'contrail:ipam_fq_name': {'allow_post': True,
                                  'allow_put': True,
                                  'default': '',
                                  'is_visible': True},
        'contrail:dns_server_address': {'allow_post': False,
                                        'allow_put': False,
                                        'is_visible': True},
    }
}


class Contrail(extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Contrail Extension"

    @classmethod
    def get_alias(cls):
        return "contrail"

    @classmethod
    def get_description(cls):
        return ("Contrail Extension")

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
# end class Contrail


class ContrailPluginBase(object):
    pass
# end class ContrailPluginBase
