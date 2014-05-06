#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

from setuptools import setup, find_packages

setup(
    name='neutron_plugin_contrail',
    version='0.1dev',
    packages=find_packages(),
    package_data={'': ['*.html', '*.css', '*.xml']},
    zip_safe=False,
    long_description="Contrail neutron plugin",
)
