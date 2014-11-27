# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2014 Juniper Networks.  All rights reserved.
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
#
# @author: Suresh Balineni 

import copy
import logging
from pprint import pformat
import sys

import cgitb

LOG = logging.getLogger(__name__)


class NeutronPluginContrailQos(object):
    def set_core(self, core_instance):
        self._core = core_instance

    def _make_qos_dict(self, entry, status_code=None, fields=None):
        return entry

    def create_qos(self, context, qos):
        """
        Creates a new Qos, and assigns it a symbolic name.
        """
        plugin_qos = copy.deepcopy(qos)

        qos_dicts = self._core._create_resource('qos', context,
                                                   plugin_qos)
        LOG.debug("create_qos(): " + pformat(qos_dicts) + "\n")

        return qos_dicts

    def get_qos(self, context, qos_id, fields=None):
        """
        Get the attributes of a qos.
        """
        qos_dicts = self._core._get_resource('qos', context, qos_id,
                                                fields)

        LOG.debug("get_qos(): " + pformat(qos_dicts))
        return qos_dicts

    def update_qos(self, context, qos_id, qos):
        """
        Updates the attributes of a particular qos.
        """
        plugin_qos = copy.deepcopy(qos)
        qos_dicts = self._core._update_resource('qos', context,
                                                   qos_id, plugin_qos)

        LOG.debug("update_qos(): " + pformat(qos_dicts))
        return qos_dicts

    def delete_qos(self, context, qos_id):
        """
        Deletes the Qos with the specified identifier
        """
        self._core._delete_resource('qos', context, qos_id)

        LOG.debug("delete_qos(): %s" % (qos_id))

    def get_qoss(self, context, filters=None, fields=None):
        """
        Retrieves all qoss identifiers.
        """
        qos_dicts = self._core._list_resource('qos', context, filters,
                                                 fields)

        LOG.debug(
            "get_qoss(): filters: " + pformat(filters) + " data: "
            + pformat(qos_dicts))
        return qos_dicts

    def get_qos_count(self, context, filters=None):
        """
        Get the count of qoss.
        """
        qoss_count = self._core._count_resource('qos', context, filters)

        LOG.debug("get_qos_count(): filters: " + pformat(filters) +
                  " data: " + str(qoss_count['count']))
        return qoss_count['count']
