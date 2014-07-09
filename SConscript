env = DefaultEnvironment().Clone()

sources = [
    'neutron_plugin_contrail/__init__.py',
    'neutron_plugin_contrail/extensions/__init__.py',
    'neutron_plugin_contrail/extensions/ipam.py',
    'neutron_plugin_contrail/extensions/policy.py',
    'neutron_plugin_contrail/extensions/vpcroutetable.py',
    'neutron_plugin_contrail/plugins/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/agent/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/agent/contrail_vif_driver.py',
    'neutron_plugin_contrail/plugins/opencontrail/contrail_plugin_core.py',
    'neutron_plugin_contrail/plugins/opencontrail/contrail_plugin_ipam.py',
    'neutron_plugin_contrail/plugins/opencontrail/contrail_plugin_policy.py',
    'neutron_plugin_contrail/plugins/opencontrail/contrail_plugin_vpc.py',
    'neutron_plugin_contrail/plugins/opencontrail/quota/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/quota/driver.py',
#   'neutron_plugin_contrail/tests/test_plugins_opencontrail_quota_driver.py',
    'neutron_plugin_contrail/tests/unit/__init__.py',
    'neutron_plugin_contrail/tests/unit/opencontrail/__init__.py',
    'neutron_plugin_contrail/tests/unit/opencontrail/__init__.py',
    'neutron_plugin_contrail/tests/unit/opencontrail/test_contrail_plugin.py',
    'requirements.txt',
    'setup.py',
    'test-requirements.txt',
]

env.Alias('neutron_plugin_contrail:test',
          env.Command(None,
                      sources, 'python setup.py nosetests',
                      chdir=Dir('.')))

