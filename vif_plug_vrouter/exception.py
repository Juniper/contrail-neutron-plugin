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

from vif_plug_vrouter.i18n import _

from os_vif import exception as vrouter_exception


class VrouterPortControlError(vrouter_exception.ExceptionBase):
    msg_fmt = _('Error during the call to vrouter-port-control: %(cmd)s')

