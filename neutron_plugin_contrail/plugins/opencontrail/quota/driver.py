# vim: tabstop=4 shiftwidth=4 softtabstop=4

import cgitb
import sys
import uuid

from vnc_api import exceptions as vnc_exc
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

DEFAULT_NEUTRON_QUOTA = -1


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
            'trunk': 'virtual_port_group',
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
        :param tenant_id: The tenant_id to check quota.
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
                 if 0 <= quotas[key] < val]
        if overs:
            raise OverQuota(overs=sorted(overs))

    @classmethod
    def get_tenant_quotas(cls, context, resources, tenant_id):
        """Given a list of resources, retrieve the quotas for the given
        tenant. If no limits are found for the specified tenant, the operation
        returns the default limits.
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param tenant_id: The ID of the tenant to return quotas for.
        :return: dict from resource name to dict of name and limit
        """
        # get default quotas
        quotas = cls.get_default_quotas(context, resources)
        tenant_quotas = cls._get_tenant_quotas(context, resources, tenant_id)
        for resource, resource_quota in tenant_quotas.items():
            # override default quota with project specific quota
            quotas[resource] = resource_quota
        return quotas
    # end get_tenant_quotas

    @classmethod
    def get_detailed_tenant_quotas(cls, context, resources, tenant_id):
        """Given a list of resources and a sepecific tenant, retrieve
        the detailed quotas (limit, used, reserved).
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return dict: mapping resource name in dict to its corresponding limit
            used and reserved. Reserved currently returns default value of 0
        """
        quotas = cls.get_tenant_quotas(context, resources, tenant_id)
        detailed_quotas = {}
        for resource, quota in quotas.items():
            detailed_quotas[resource] = {
                'limit': quota,
                'used': cls._get_used_quota(resource, tenant_id),
                'reserved': 0,  # zero is a default value in Neutron driver
            }
        return detailed_quotas
    # end get_detailed_tenant_quotas

    @classmethod
    def _get_used_quota(cls, resource, tenant_id):
        """Get used quota of given resource for tenant.
        :param resource: String with resource name.
        :param tenant_id: String with project ID
        """
        return 0  # TODO(pawel.zadrozny): Find a way to count used resources
    # end _get_used_quota

    @classmethod
    def get_all_quotas(cls, context, resources):
        """Given a list of resources, retrieve the quotas for the all tenants.
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :return: quotas list of dict of tenant_id:, resourcekey1:
        resourcekey2: ...
        """
        default_quota = cls.get_default_quotas(context, resources)
        project_list = cls._get_vnc_conn().projects_list()['projects']
        ret_list = []
        for project in project_list:
            if default_quota and cls._is_default_project(project):
                continue
            quotas = cls._get_tenant_quotas(context, resources,
                                            project['uuid'])
            if quotas:
                quotas['tenant_id'] = project['uuid'].replace('-', '')
                ret_list.append(quotas)
        return ret_list
    # end get_all_quotas

    @classmethod
    def _get_tenant_quotas(cls, context, resources, tenant_id):
        """Get quotas of a tenant.
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param tenant_id: The ID of the tenant to return quotas for.
        """
        project_id = str(uuid.UUID(tenant_id))
        try:
            project = cls._get_vnc_conn().project_read(id=project_id)
        except vnc_exc.NoIdError:
            return {}
        except Exception as exc:
            cgitb.Hook(format="text").handle(sys.exc_info())
            raise exc

        project_quotas = project.get_quota()
        qn2c = cls.quota_neutron_to_contrail_type

        quotas = {}
        for resource in resources:
            if project_quotas and resource in qn2c:
                resource_quota = getattr(project_quotas, qn2c[resource], None)
                if resource_quota is not None:
                    quotas[resource] = resource_quota
        return quotas
    # end _get_tenant_quotas

    @classmethod
    def _is_default_project(cls, project):
        return project['fq_name'] == ['default-domain', 'default-project']

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
    def get_default_quotas(cls, context, resources, tenant_id=None):
        """Given a list of resources, retrieve the default quotas set for
        a tenant.
        :param context: The request context, for access checks.
        :param resources: A dictionary of the registered resource keys.
        :param tenant_id: The ID of the tenant to return default quotas for.
        :return: dict from resource name to dict of name and limit
        """
        try:
            project = cls._get_vnc_conn().project_read(
                fq_name=['default-domain', 'default-project'])
            project_quotas = project.get_quota()
        except vnc_exc.NoIdError:
            project_quotas = None

        qn2c = cls.quota_neutron_to_contrail_type
        quotas = {}
        for resource in resources:
            if project_quotas and resource in qn2c:
                quota = getattr(project_quotas, qn2c[resource], None)
                if quota is None:
                    quota = project_quotas.get_defaults()
            else:
                # If there is no Contrail Quota for that resource use
                # Neutron's default quota value
                quota = DEFAULT_NEUTRON_QUOTA
            quotas[resource] = quota
        return quotas
    # end get_default_quotas
