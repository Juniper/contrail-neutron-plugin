# Copyright 2017 Juniper Networks.  All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import re

# Contrail VNC API defaults
VNC_API_DEFAULT_HOST = '127.0.0.1'
VNC_API_DEFAULT_PORT = 8082
VNC_API_DEFAULT_BASE_URL = '/'
VNC_API_DEFAULT_USE_SSL = False
VNC_API_DEFAULT_INSECURE = False
VNC_API_DEFAULT_TIMEOUT = 120
VNC_API_DEFAULT_CONN_TIMEOUT = 5

# Keystone defaults
KEYSTONE_AUTH = 'keystone'
KEYSTONE_V2_API_VERSION = '/v2.0/'
KEYSTONE_V3_API_VERSION = '/v3/'
KEYSTONE_V2_REGEX = re.compile(r'%s?$' % KEYSTONE_V2_API_VERSION)
KEYSTONE_V3_REGEX = re.compile(r'%s?$' % KEYSTONE_V3_API_VERSION)
