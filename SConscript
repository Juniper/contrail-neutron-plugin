env = DefaultEnvironment().Clone()

sources = [
    '.coveragerc',
    '.stestr.conf',
    'MANIFEST.in',
    'README.rst',
    'requirements.txt',
    'setup.py',
    'test-requirements.txt',
    'tox.ini',
    'neutron_plugin_contrail',
]

source_rules = [env.Install(Dir('.'), "#openstack/neutron_plugin/" + f)
                for f in sources]

cd_cmd = 'cd ' + Dir('.').path + ' && '
sdist_gen = env.Command('dist/neutron_plugin_contrail-0.1dev.tar.gz', 'setup.py',
                        cd_cmd + 'python setup.py sdist')

env.Depends(sdist_gen, source_rules)
env.Default(sdist_gen)

if 'install' in BUILD_TARGETS:
    install_cmd = env.Command(None, 'setup.py',
                              cd_cmd + 'python setup.py install %s' %
                              env['PYTHON_INSTALL_OPT'])
    env.Depends(install_cmd, sdist_gen)
    env.Alias('install', install_cmd)

test_target = env.SetupPyTestSuite(
    sdist_gen,
    '/config/vnc_openstack/dist',
    '/config/api-server/dist',
    use_tox=True)
# Local Variables:
# mode: python
# End:
