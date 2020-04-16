#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

from setuptools import setup, find_packages

def requirements(filename):
    with open(filename) as f:
        lines = f.read().splitlines()
    return lines

setup(
    name='neutron_plugin_contrail',
    version='0.1dev',
    packages=find_packages(),
    package_data={'': ['*.html', '*.css', '*.xml']},
    zip_safe=False,
    long_description="Contrail neutron plugin",

    install_requires=requirements('requirements.txt'),

    test_suite='neutron_plugin_contrail.tests',
    tests_require=requirements('test-requirements.txt'),

    entry_points={
        'neutron.service_plugins': [
            'contrail-timestamp = neutron_plugin_contrail.plugins.opencontrail.services.timestamp.timestamp_plugin:TimeStampPlugin',
            'contrail-trunk = neutron_plugin_contrail.plugins.opencontrail.services.trunk.plugin:TrunkPlugin',
            'contrail-tags = neutron_plugin_contrail.plugins.opencontrail.services.tags.tags_plugin:TagsPlugin',
        ],
        'firewall_drivers': [
            'contrail-fwaasv2 = neutron_plugin_contrail.plugins.opencontrail.neutron_fwaas.contrail:ContrailFirewallv2Driver',
        ],
    },
)
