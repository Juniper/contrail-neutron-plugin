#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import re

from setuptools import find_packages
from setuptools import setup


def requirements(filename):
    with open(filename) as f:
        lines = f.read().splitlines()
    c = re.compile(r'\s*#.*')
    return filter(bool, map(lambda y: c.sub('', y).strip(), lines))


setup(
    name='networking-contrail',
    version='0.1dev',
    long_description=open('README.rst').read(),
    packages=find_packages(),
    install_requires=requirements('requirements.txt'),
    tests_require=requirements('test-requirements.txt'),
    author_email='dev@lists.opencontrail.org',
    url='https://github.com/Juniper/contrail-neutron-plugin',
    classifier=[
        'Environment :: OpenStack',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    entry_points={
        'neutron.core_plugins': [
            'contrail = networking_contrail.plugin.plugin:ContrailPlugin',
            # for backward compatibility with old plugin structure:
            'neutron_plugin_contrail.plugins.opencontrail.contrail_plugin.NeutronPluginContrailCoreV2 = networking_contrail.plugin.plugin:ContrailPlugin',
        ],
        'neutron.service_plugins': [
            'contrail-timestamp = networking_contrail.services.timestamp.timestamp_plugin:TimeStampPlugin',
            'contrail-lbaasv2 = networking_contrail.services.loadbalancer.v2.plugin:LoadBalancerPluginV2',
            # for backward compatibility with old plugin structure:
            'neutron_plugin_contrail.plugins.opencontrail.loadbalancer.v2.plugin.LoadBalancerPluginV2 = networking_contrail.services.loadbalancer.v2.plugin:LoadBalancerPluginV2',
        ],
        'firewall_drivers': [
            'contrail-fwaasv2 = networking_contrail.services.neutron_fwaas.contrail:ContrailFirewallv2Driver',
        ],
    },
    test_suite='networking_contrail.tests',
)
