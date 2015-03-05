#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

from setuptools import setup

def requirements(filename):
    with open(filename) as f:
        lines = f.read().splitlines()
    return lines

setup(
    setup_requires=['pbr'],
    pbr=True,
    zip_safe=False,
    long_description="Contrail neutron plugin",

    install_requires=requirements('requirements.txt'),

    test_suite='neutron_plugin_contrail.tests',
    tests_require=requirements('test-requirements.txt'),
)
