try:
    from neutron.services.loadbalancer.drivers import abstract_driver
except ImportError:
    from neutron_lbaas.services.loadbalancer.drivers import abstract_driver

"""Dummy LBAAS driver for OpenContrail.

This allows to specify a default provider in the neutron.conf.

LBAAS drivers are now in contrail svc_monitor.
"""


class OpencontrailLoadbalancerDummyDriver(
        abstract_driver.LoadBalancerAbstractDriver):

    def __init__(self, plugin):
        pass

    def create_vip(self, context, vip):
        pass

    def update_vip(self, context, old_vip, vip):
        pass

    def delete_vip(self, context, vip):
        pass

    def create_pool(self, context, pool):
        pass

    def update_pool(self, context, old_pool, pool):
        pass

    def delete_pool(self, context, pool):
        pass

    def stats(self, context, pool_id):
        pass

    def create_member(self, context, member):
        pass

    def update_member(self, context, old_member, member):
        pass

    def delete_member(self, context, member):
        pass

    def update_pool_health_monitor(self, context,
                                   health_monitor,
                                   pool_id):
        pass

    def create_pool_health_monitor(self, context,
                                   health_monitor,
                                   pool_id):
        pass

    def delete_pool_health_monitor(self, context, health_monitor, pool_id):
        pass
