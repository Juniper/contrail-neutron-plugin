# vim: tabstop=4 shiftwidth=4 softtabstop=4

import cgitb
import sys
import uuid

from cfgm_common import exceptions as vnc_exc
try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging
try:
    from neutron.common.exceptions import InvalidQuotaValue
except ImportError:
    from neutron_lib.exceptions import InvalidQuotaValue
try:
    from neutron.common.exceptions import OverQuota
except ImportError:
    from neutron_lib.exceptions import OverQuota
from vnc_api import vnc_api
try:
    from neutron.db.quota import api as quota_api
except ImportError:
    pass

from neutron_plugin_contrail.common import utils

LOG = logging.getLogger(__name__)

vnc_conn = None


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
            'route_table': 'route_table',
            'security_group': 'security_group',
            'security_group_rule': 'security_group_rule',
            'router': 'logical_router',
            'port': 'virtual_machine_interface',
            'pool': 'loadbalancer_pool',
            'vip': 'virtual_ip',
            'member': 'loadbalancer_member',
            'health_monitor': 'loadbalancer_healthmonitor',
            'firewall_group': 'firewall_group',
            'firewall_policy': 'firewall_policy',
            'firewall_rule': 'firewall_rule',
            }

    @classmethod
    def _get_vnc_conn(cls):
        global vnc_conn
        if vnc_conn:
            return vnc_conn

        vnc_conn = utils.get_vnc_api_instance()
        return vnc_conn
    # end _get_vnc_conn

    def limit_check(self, context, tenant_id, resources, values):
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
        # Ensure no value is less than zero
        unders = [key for key, val in values.items() if val < 0]
        if unders:
            raise InvalidQuotaValue(unders=sorted(unders))

        # Get the applicable quotas
        quotas = self.__class__.get_tenant_quotas(
            context, resources, tenant_id)

        # Check the quotas and construct a list of the resources that
        # would be put over limit by the desired values
        overs = [key for key, val in values.items()
                 if quotas[key] >= 0 and quotas[key] < val]
        if overs:
            raise OverQuota(overs=sorted(overs))

    @classmethod
    def get_tenant_quotas(cls, context, resources, tenant_id):
        try:
            default_project = cls._get_vnc_conn().project_read(
                fq_name=['default-domain', 'default-project'])
            default_quota = default_project.get_quota()
        except vnc_exc.NoIdError:
            default_quota = None
        return cls._get_tenant_quotas(context, resources, tenant_id,
                                      default_quota)

    @classmethod
    def _get_tenant_quotas(cls, context, resources, tenant_id,
                           default_quota, get_default=True):
        """Get quotas of a tenant.

        :param get_default: if False, does not return quotas if they
        only contain default values.
        """
        try:
            proj_id = str(uuid.UUID(tenant_id))
            proj_obj = cls._get_vnc_conn().project_read(id=proj_id)
            quota = proj_obj.get_quota()
        except vnc_exc.NoIdError:
            return {}
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        qn2c = cls.quota_neutron_to_contrail_type
        quotas = {}
        has_non_default = False
        for resource in resources:
            quota_res = None
            if quota and resource in qn2c:
                quota_res = getattr(quota, qn2c[resource], None)
                if quota_res is not None:
                    has_non_default = True
            if quota_res is None and default_quota and resource in qn2c:
                quota_res = getattr(default_quota, qn2c[resource], None)
                if quota_res is None:
                    quota_res = default_quota.get_defaults()
            if quota_res is None:
                quota_res = resources[resource].default
            quotas[resource] = quota_res

        if not get_default and not has_non_default:
            return {}
        return quotas

    @classmethod
    def get_all_quotas(cls, context, resources):
        try:
            default_project = cls._get_vnc_conn().project_read(
                fq_name=['default-domain', 'default-project'])
            default_quota = default_project.get_quota()
        except vnc_exc.NoIdError:
            default_quota = None

        project_list = cls._get_vnc_conn().projects_list()['projects']
        ret_list = []
        for project in project_list:
            if default_quota and (project['uuid'] == default_project.uuid):
                continue
            quotas = cls._get_tenant_quotas(context, resources,
                                            project['uuid'], default_quota,
                                            get_default=False)
            if quotas != {}:
                quotas['tenant_id'] = project['uuid'].replace('-', '')
                ret_list.append(quotas)
        return ret_list

    @classmethod
    def delete_tenant_quota(cls, context, tenant_id):
        try:
            proj_id = str(uuid.UUID(tenant_id))
            proj_obj = cls._get_vnc_conn().project_read(id=proj_id)
            quota = proj_obj.get_quota()
        except vnc_exc.NoIdError:
            return
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        if quota is not None:
            for k, v in quota.__dict__.items():
                if k != 'defaults':
                    quota.__dict__[k] = None
            proj_obj.set_quota(quota)
            cls._get_vnc_conn().project_update(proj_obj)

    @classmethod
    def update_quota_limit(cls, context, tenant_id, resource, limit):
        try:
            proj_id = str(uuid.UUID(tenant_id))
            proj_obj = cls._get_vnc_conn().project_read(id=proj_id)
            quota = proj_obj.get_quota() or vnc_api.QuotaType()
        except vnc_exc.NoIdError:
            return
        except Exception as e:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise e

        qn2c = cls.quota_neutron_to_contrail_type
        if resource in qn2c:
            quota_method = 'set_' + qn2c[resource]
            set_quota = getattr(quota, quota_method)
            set_quota(limit)
            proj_obj.set_quota(quota)
            cls._get_vnc_conn().project_update(proj_obj)

    def make_reservation(self, context, tenant_id, resources, deltas, plugin):
        """This driver does not support reservations.

        This routine is provided for backward compatibility purposes with
        the API controllers which have now been adapted to make reservations
        rather than counting resources and checking limits - as this
        routine ultimately does.
        """
        return quota_api.ReservationInfo('fake', None, None, None)

    def commit_reservation(self, context, reservation_id):
        """Tnis is a noop as this driver does not support reservations."""

    def cancel_reservation(self, context, reservation_id):
        """Tnis is a noop as this driver does not support reservations."""

    @classmethod
    def get_default_quotas(cls, context, resources, tenant_id):
        try:
            default_project = cls._get_vnc_conn().project_read(
                fq_name=['default-domain', 'default-project'])
            default_quota = default_project.get_quota()
        except vnc_exc.NoIdError:
            default_quota = None

        qn2c = cls.quota_neutron_to_contrail_type
        quotas = {}
        for resource in resources:
            quota_res = None
            if default_quota and resource in qn2c:
                quota_res = getattr(default_quota, qn2c[resource], None)
                if quota_res is None:
                    quota_res = default_quota.get_defaults()
            quotas[resource] = quota_res
        return quotas
