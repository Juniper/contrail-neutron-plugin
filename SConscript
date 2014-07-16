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
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/driver.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/loadbalancer_db.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/loadbalancer_healthmonitor.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/loadbalancer_member.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/loadbalancer_pool.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/plugin.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/resource_manager.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/utils.py',
    'neutron_plugin_contrail/plugins/opencontrail/loadbalancer/virtual_ip.py',
    'neutron_plugin_contrail/plugins/opencontrail/quota/__init__.py',
    'neutron_plugin_contrail/plugins/opencontrail/quota/driver.py',
#   'neutron_plugin_contrail/tests/test_plugins_opencontrail_quota_driver.py',
    'neutron_plugin_contrail/tests/__init__.py',
    'neutron_plugin_contrail/tests/loadbalancer/__init__.py',
    'neutron_plugin_contrail/tests/loadbalancer/test_driver.py',
    'neutron_plugin_contrail/tests/loadbalancer/test_plugin.py',
    'neutron_plugin_contrail/tests/unit/__init__.py',
    'neutron_plugin_contrail/tests/unit/opencontrail/__init__.py',
    'neutron_plugin_contrail/tests/unit/opencontrail/test_contrail_plugin.py',
    'requirements.txt',
    'setup.py',
    'test-requirements.txt',
]

packages = [
    '%s/api-lib/dist/vnc_api-0.1dev.tar.gz' % env['TOP'],
    '%s/config/common/dist/cfgm_common-0.1dev.tar.gz' % env['TOP'],
]

import os
def BuildPyTestSetup(env, target, source):
    file = open(target[0].abspath, 'w')
    file.write("[easy_install]\nfind_links =")
    for pkg in source:
        dependency = env.File(pkg)
        file.write(" %s" % os.path.dirname(dependency.abspath))
    file.write("\n")
    file.close()
    return

def GeneratePyTestSetup(env, targets, source):
    """
    Generate a setup.cfg file that contains a list of directories
    where dependent packages can be found. The fact that package directory
    list is being given as a source automatically adds them as dependencies.
    """
    target = env.File('setup.cfg')
    return env.Command(target=target, source=source, action=BuildPyTestSetup);

env.Append(BUILDERS = {'PythonTestSetup': GeneratePyTestSetup})
test_sources = sources
test_sources += env.PythonTestSetup(source=packages)

env.Alias('neutron_plugin_contrail:test',
          env.Command(None,
                      test_sources, 'python setup.py nosetests',
                      chdir=Dir('.')))

# Local Variables:
# mode: python
# End:
