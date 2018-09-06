# Copyright 2018 Juniper Networks.  All rights reserved.
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

from neutron_lib import exceptions
from neutron_lib.db import constants as db_const
from neutron_lib.db import model_base
from neutron_lib.db import utils as db_utils
from oslo_log import log as logging
from oslo_versionedobjects import fields as obj_fields
from neutron.objects import base as object_base
from neutron.objects import common_types
import sqlalchemy as sa

from neutron_plugin_contrail.extensions.dummy import DummyServicePluginBase
from neutron_plugin_contrail.plugins.opencontrail.services.dummy import dummy_api_def


LOG = logging.getLogger(__name__)


class Dummy(model_base.BASEV2, model_base.HasId, model_base.HasProject):
    name = sa.Column(sa.String(db_const.NAME_FIELD_SIZE))


@object_base.NeutronObjectRegistry.register
class DummyDBObject(object_base.NeutronDbObject):
    VERSION = '1.0'
    db_model = Dummy
    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(nullable=True),
        'name': obj_fields.StringField(nullable=True),
    }


class DummyServicePlugin(DummyServicePluginBase):
    def __init__(self):
        super(DummyServicePlugin, self).__init__()
        self._dummys = {}

    def _get_dummy(self, context, id):
        obj = DummyDBObject.get_object(context, id=id)
        if not obj:
            raise exceptions.NotFound()
        return obj

    def create_dummy(self, context, dummy):
        d = dummy[dummy_api_def.RESOURCE_NAME]
        obj = DummyDBObject(
            context,
            name=d['name'],
            project_id=d['project_id'])
        obj.create()
        return obj.to_dict()

    def get_dummys(self, context, filters=None, fields=None,
                   sorts=None, limit=None, marker=None, page_reverse=False):
        pager = object_base.Pager(sorts, limit, page_reverse, marker)
        filters = filters or {}
        objs = DummyDBObject.get_objects(context, _pager=pager, **filters)
        return [db_utils.resource_fields(obj.to_dict(), fields)
                for obj in objs]

    def get_dummy(self, context, id, fields=None):
        return db_utils.resource_fields(
            self._get_dummy(context, id).to_dict(), fields)

    def update_dummy(self, context, id, dummy):
        obj = self._get_flavor(context, id)
        obj.update_fields(dummy[dummy_api_def.RESOURCE_NAME])
        obj.update()
        return obj.to_dict()

    def delete_dummy(self, context, id):
        self._get_dummy(context, id).delete()
