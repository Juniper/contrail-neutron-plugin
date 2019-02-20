try:
    from neutron.api.extensions import ExtensionDescriptor
except ImportError:
    from neutron_lib.api.extensions import ExtensionDescriptor


EXTENDED_ATTRIBUTES_2_0 = {
    'networks': {
        'fq_name': {'allow_post': False,
                    'allow_put': False,
                    'is_visible': True},
        'instance_count': {'allow_post': False,
                           'allow_put': False,
                           'is_visible': True},
        'policys': {'allow_post': True,
                    'allow_put': True,
                    'default': '',
                    'is_visible': True},
        'subnet_ipam': {'allow_post': False,
                        'allow_put': False,
                        'default': '',
                        'is_visible': True},
    },
    'routers': {
        'fq_name': {'allow_post': False,
                    'allow_put': False,
                    'is_visible': True},
    },
    'security_groups': {
        'fq_name': {'allow_post': False,
                    'allow_put': False,
                    'is_visible': True},
    },
    'subnets': {
        'instance_count': {'allow_post': False,
                           'allow_put': False,
                           'is_visible': True},
        'ipam_fq_name': {'allow_post': True,
                         'allow_put': True,
                         'default': '',
                         'is_visible': True},
        'dns_server_address': {'allow_post': False,
                               'allow_put': False,
                               'is_visible': True},
    },
    'ports': {
        'service_instance_ips': {'allow_post': False,
                                 'allow_put': False,
                                 'is_visible': True},
        'service_health_check_ips': {'allow_post': False,
                                     'allow_put': False,
                                     'is_visible': True},
        'secondary_ips': {'allow_post': False,
                          'allow_put': False,
                          'is_visible': True},
    },
}


class Contrail(ExtensionDescriptor):

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
        """Return Ext Resources."""
        exts = []
        return exts

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}


class ContrailPluginBase(object):
    pass
