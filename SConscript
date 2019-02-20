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
    'networking_contrail',
]

source_rules = [env.Install(Dir('.'), "#openstack/neutron_plugin/" + f)
                for f in sources]

cd_cmd = 'cd ' + Dir('.').path + ' && '
sdist_gen = env.Command('dist/networking-contrail-0.1dev.tar.gz', 'setup.py',
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
    env.GetVncAPIPkg(),
    '/config/vnc_openstack/dist',
    use_tox=True)
# Local Variables:
# mode: python
# End:
