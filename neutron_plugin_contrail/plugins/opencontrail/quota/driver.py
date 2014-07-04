# vim: tabstop=4 shiftwidth=4 softtabstop=4

import ConfigParser
from pprint import pformat

from neutron.openstack.common import log as logging

from oslo.config import cfg
from httplib2 import Http
import re
import string
import sys
import cgitb
import uuid
import time
from neutron.common import exceptions
from neutron_plugin_contrail.plugins.opencontrail.contrailplugin import ContrailPlugin
from vnc_api.vnc_api import *

LOG = logging.getLogger(__name__)

class QuotaDriver(object):
    """Configuration driver.

    Driver to perform necessary checks to enforce quotas and obtain
    quota information. The default driver utilizes the default values
    in neutron.conf.
    """
    quota_neutron_to_contrail_type = {
            'subnet': 'subnet',
            'network': 'virtual_network',
            'floatingip': 'floating_ip',
            'route_table': 'logical_router',
            'security_group': 'security_group',
            'security_group_rule': 'security_group_rule',
            'router': 'logical_router',
            'port': 'virtual_machine_interface',
            };

    def _get_quotas(self, context, resources, keys):
        """Get quotas.

        A helper method which retrieves the quotas for the specific
        resources identified by keys, and which apply to the current
        context.

        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resources.
        :param keys: A list of the desired quotas to retrieve.
        """
        # Filter resources
        desired = set(keys)
        sub_resources = dict((k, v) for k, v in resources.items()
                             if k in desired)

        # Make sure we accounted for all of them...
        if len(keys) != len(sub_resources):
            unknown = desired - set(sub_resources.keys())
            raise exceptions.QuotaResourceUnknown(unknown=sorted(unknown))
        quotas = {}
        for resource in sub_resources.values():
            quotas[resource.name] = resource.default
        return quotas

    def limit_check(self, context, tenant_id,
                    resources, values):
        """Check simple quota limits.

        For limits--those quotas for which there is no usage
        synchronization function--this method checks that a set of
        proposed values are permitted by the limit restriction.

        This method will raise a QuotaResourceUnknown exception if a
        given resource is unknown or if it is not a simple limit
        resource.

        If any of the proposed values is over the defined quota, an
        OverQuota exception will be raised with the sorted list of the
        resources which are too high.  Otherwise, the method returns
        nothing.

        :param context: The request context, for access checks.
        :param tennant_id: The tenant_id to check quota.
        :param resources: A dictionary of the registered resources.
        :param values: A dictionary of the values to check against the
                       quota.
        """

    @staticmethod
    def get_tenant_quotas(context, resources, tenant_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
        try:
            project_uuid = str(uuid.UUID(tenant_id))
            proj_obj = cfgdb._project_read(project_uuid)
        except (ValueError, NoIdError):
            return {}
        try:
            quota = proj_obj.get_quota()
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        qn2c = QuotaDriver.quota_neutron_to_contrail_type
        quotas = {}
        sub_resources = dict((k, v) for k, v in resources.items())
        for resource in sub_resources.values():
            if quota and resource.name in qn2c.keys():
                quotas[resource.name] = quota.__dict__[qn2c[resource.name]] or quota.get_defaults()
            else:
                quotas[resource.name] = resource.default
        return quotas

    @staticmethod
    def get_all_quotas(context, resources):
        return [QuotaDriver.get_tenant_quotas(context, resources, context.tenant_id)]

    @staticmethod
    def delete_tenant_quota(context, tenant_id):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
        try:
            project_uuid = str(uuid.UUID(tenant_id))
            proj_obj = cfgdb._project_read(project_uuid)
        except (ValueError, NoIdError):
            return
        try:
            quota = proj_obj.get_quota()
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        for k,v in quota.__dict__.items():
            if k != 'defaults':
                quota.__dict__[k] = quota.defaults
        proj_obj.set_quota(quota)
        cfgdb._vnc_lib.project_update(proj_obj)

    @staticmethod
    def update_quota_limit(context, tenant_id, resource, limit):
        try:
            cfgdb = ContrailPlugin._get_user_cfgdb(context)
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e
        try:
            project_uuid = str(uuid.UUID(tenant_id))
            for i in range(10):
                try:
                    proj_obj = cfgdb._project_read(proj_id)
                    break
                except Exception as e:
                    time.sleep(2)
            proj_obj = cfgdb._project_read(project_uuid)
        except (ValueError, NoIdError):
            return {}
        try:
            quota = proj_obj.get_quota()
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        qn2c = QuotaDriver.quota_neutron_to_contrail_type
        if resource in qn2c.keys():
            quota_method = 'set_' + qn2c[resource]
            set_quota = getattr(quota, quota_method)
            set_quota(limit)
            proj_obj.set_quota(quota)
            cfgdb._vnc_lib.project_update(proj_obj)
