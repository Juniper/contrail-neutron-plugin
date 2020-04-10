import mock
import unittest
import uuid

from neutron_plugin_contrail.plugins.opencontrail.quota.driver import QuotaDriver

class ContrailPluginQuotaDriverTest(unittest.TestCase):
    def setUp(self):
        print("setup quota")

    def test_testenv(self):
        print("testenv quota ok")

    def test_get_tenant_quotas_arg(self):
        """Call neutron_plugin_contrail.plugins.opencontrail.quota.driver.QuotaDriver.[ _get_quotas, get_all_quotas ]"""

        class MockContext():
            tenant_id = 'f00dbeef012f411b89d68928ee8703ee'

        class MockResource():
            name = 'default'
            default = -1
            def __init__(self, name = 'default', default = -1):
                self.name = name
                self.default = default
            
        driver = QuotaDriver()
        ctx = MockContext()

        foo_quotas = {'network': 5}
        default_quotas = {'network': MockResource('network', 5) }
        target_tenant = 'f00dbeef012f411b89d68928ee8703ee'

        with mock.patch.object(QuotaDriver,
                               'get_tenant_quotas',
                               return_value=foo_quotas) as get_tenant_quotas:

            quotas = driver._get_quotas(ctx,
                                        default_quotas,
                                        ['network'])
            self.assertEqual(quotas, foo_quotas)

            quotas = driver.get_all_quotas(ctx,
                                           default_quotas)
            self.assertEqual(quotas[0], foo_quotas)
            get_tenant_quotas.assert_called_once_with(ctx,
                                                      default_quotas,
                                                      target_tenant)
