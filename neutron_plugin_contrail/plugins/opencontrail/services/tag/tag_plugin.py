# Copyright 2020 Juniper Networks.  All rights reserved.
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

from neutron_lib.plugins import directory

from neutron.db import standard_attr
from neutron.extensions import tagging
from neutron.objects import tag as tag_obj


# Taggable resources
resource_model_map = standard_attr.get_standard_attr_resource_model_map()


class TagPlugin(tagging.TagPluginBase):
    """Implementation of the Neutron Tag Service Plugin."""

    supported_extension_aliases = ['standard-attr-tag']

    __filter_validation_support = True

    @property
    def _core_plugin(self):
        return directory.get_plugin()

    def get_tags(self, context, parent, parent_id):
        """Get tags for resource.
        # GET /v2.0/networks/{network_id}/tags

        :param context: Request context
        :param parent: Tagged neutron resource
        :param parent_id: Tagged neutron resource id
        :return:
        """
        filters = {'parent_id': parent_id}
        return self._core_plugin._list_resource('tags', context, filters)

    def get_tag(self, context, parent, parent_id, id):
        """Get tag for resource.
        # GET /v2.0/networks/{network_id}/tags/{tag}
        # id == tag

        :param context: Request context
        :param parent: Tagged neutron resource
        :param parent_id: Tagged neutron resource id
        :param id: Tag id
        :return:
        """
        req_data = {'filters': {'parent_id': parent_id, 'tag': id}}
        self._core_plugin._request_backend(context, req_data,
                                           'tags', 'READ')

    def update_tag(self, context, parent, parent_id, id):
        """Add tag to a resource.
        # PUT /v2.0/networks/{network_id}/tags/{tag}
        # id == tag

        :param context: Request context
        :param parent: Tagged neutron resource
        :param parent_id: Tagged neutron resource id
        :param id: Tag name
        :return:
        """
        return self.update_tags(context, parent, parent_id, {'tags': [id]})[0]

    def update_tags(self, context, parent, parent_id, body):
        """Add multiple tags to a resource.
        # PUT /v2.0/networks/{network_id}/tags/
        # body: {"tags": ["aaa", "bbb"]}

        :param context: Request context
        :param parent: Tagged neutron resource
        :param parent_id: Tagged neutron resource id
        :param body: Dict with list of tags
        :return:
        """
        # if list of tags is empty, delete all
        if 'tags' not in body or not body['tags']:
            return self.delete_tags(context, parent, parent_id)

        res_data = {
            'tags': {
                'resource': {'parent_id': parent_id, 'tags': body['tags']}
            }
        }
        return self._core_plugin._create_resource('tags', context, res_data)

    def delete_tag(self, context, parent, parent_id, id):
        """Delete reference to tag from resource.
        # DELETE /v2.0/networks/{network_id}/tags/{tag}

        :param context: Request context
        :param parent: Tagged neutron resource
        :param parent_id: Tagged neutron resource id
        :param id: Tag id
        """
        req_data = {'resource': {'parent_id': parent_id, 'tag': id}}
        self._core_plugin._request_backend(context, req_data,
                                           'tags', 'DELETE')

    def delete_tags(self, context, parent, parent_id):
        """Delete references to all tags from resource.
        # DELETE /v2.0/networks/{network_id}/tags

        :param context:
        :param parent:
        :param parent_id:
        """
        req_data = {'resource': {'parent_id': parent_id}}
        self._core_plugin._request_backend(context, req_data,
                                           'tags', 'DELETEALL')
