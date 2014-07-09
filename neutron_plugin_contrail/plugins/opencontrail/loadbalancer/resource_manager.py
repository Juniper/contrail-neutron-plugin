#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

from abc import ABCMeta, abstractmethod, abstractproperty
from eventlet import greenthread
from neutron.common import exceptions as n_exc
from neutron.plugins.common import constants
import six

@six.add_metaclass(ABCMeta)
class ResourceManager(object):
    _max_project_read_attempts = 3

    def __init__(self, api):
        self._api = api

    @abstractproperty
    def property_type_mapping(self):
        """ Mapping from property name to neutron dict key.
        """
        pass

    @abstractmethod
    def make_properties(self, resource):
        """ Returns the properties for the specified resource.
        """
        pass

    @abstractmethod
    def make_dict(self, resource, fields):
        """ Return the contrail api resource in the dictionary format
        expected by neutron.
        """
        pass

    @abstractmethod
    def resource_read(self, id):
        """ Read the specified resource from the api server.
        """
        pass

    @abstractmethod
    def resource_list(self, parent_id):
        """ Returns the list of objects from the api server.
        """
        pass

    @abstractmethod
    def resource_delete(self, id):
        """ Delete the specified resource from the api server.
        """
        pass

    @abstractproperty
    def get_exception_notfound(self, id):
        """ Returns the correct NotFound exception.
        """
        pass

    @abstractproperty
    def resource_name_plural(self):
        """ Resource list name in a list response.
        """
        pass

    @abstractmethod
    def create(self, context, resource):
        """ Create resource.
        """
        pass

    @abstractmethod
    def update(self, context, id, resource):
        """ Create resource.
        """
        pass

    @abstractmethod
    def update(self, context, id, resource):
        """ Create resource.
        """
        pass

    def _get_tenant_id_for_create(self, context, resource):
        if context.is_admin and 'tenant_id' in resource:
            tenant_id = resource['tenant_id']
        elif ('tenant_id' in resource and
              resource['tenant_id'] != context.tenant_id):
            reason = 'Cannot create resource for another tenant'
            raise n_exc.AdminRequired(reason=reason)
        else:
            tenant_id = context.tenant_id
        return tenant_id

    def _get_resource_name(self, resource, parent, name, uuid):
        """ Generate an unique name. This is display name if there are
        no conflicts or display_name + uuid.
        """
        fq_name = list(parent.fq_name)
        fq_name.append(name)
        obj = self._api.fq_name_to_id(resource, fq_name)
        if obj is None:
            return name
        return name + '_' + uuid

    def _is_authorized(self, context, resource):
        return context.is_admin or context.tenant_id == resource['tenant_id']

    def _project_read(self, project_id):
        """ Reads the project from the api server. The project will be
        created it does not yet exist.
        """
        for i in range(self._max_project_read_attempts):
            try:
                return self._api.project_read(id=project_id)
            except NoIdError:
                pass
            greenthread.sleep(1)
        raise n_exc.TenantNetworksDisabled()

    def _fields(self, resource, fields):
        if fields:
            return dict(((key, item) for key, item in resource.items()
                         if key in fields))
        return resource

    def _apply_filter(self, resource, filters):
        if filters is None:
            return True
        for key, value in filters.iteritems():
            if key in resource and not resource[key] in value:
                return False
        return True

    def _get_object_status(self, obj):
        id_perms = obj.get_id_perms()
        if id_perms and id_perms.enable:
            return constants.ACTIVE
        return constants.PENDING_DELETE

    def _get_object_description(self, obj):
        id_perms = obj.get_id_perms()
        if id_perms is None:
            return None
        return id_perms.description

    def get_resource(self, context, id, fields=None):
        """ Implement GET by uuid.
        """
        try:
            obj = self.resource_read(id=id)
        except NoIdError:
            raise self.get_exception_notfound(id=id)
        if not context.is_admin and context.tenant_id != obj.parent_uuid:
            raise self.get_exception_notfound(id=id)
        return self.make_dict(obj, fields)

    def get_collection(self, context, filters=None, fields=None):
        """ Generic implementation of list command.
        """

        def get_resource_dict(uuid, filters, fields):
            try:
                obj = self.resource_read(id=uuid)
            except NoIdError:
                return None
            res = self.make_dict(obj, None)
            if not self._apply_filter(res, filters):
                return None
            return self._fields(res, fields)

        response = []

        if filters and 'id' in filters:
            for v in filters['id']:
                res = get_resource_dict(v, filters, fields)
                if res is not None and self._is_authorized(context, res):
                    response.append(res)
            return response

        parent_id = None
        if not context.is_admin:
            parent_id = context.tenant_id
        obj_list = self.resource_list(parent_id=parent_id)

        if self.resource_name_plural not in obj_list:
            return response

        for v in obj_list[self.resource_name_plural]:
            res = get_resource_dict(v['uuid'], filters, fields)
            if res is not None:
                response.append(res)
        return response

    def delete(self, context, id):
        if not context.is_admin:
            try:
                obj = self.resource_read(id=id)
            except NoIdError:
                raise self.get_exception_notfound(id=id)
            if context.tenant_id != obj.parent_uuid:
                raise n_exc.NotAuthorized()

        # TODO: possible exceptions: RefsExistError
        try:
            self.resource_delete(id=id)
        except NoIdError:
            raise self.get_exceptin_notfound(id=id)
