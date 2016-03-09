#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#
from neutron.api.v2 import attributes
from neutron.common import exceptions as n_exc
from neutron.common import constants as n_constants

from neutron_lbaas.extensions import loadbalancerv2

try:
    from neutron.openstack.common import log as logging
except ImportError:
    from oslo_log import log as logging

try:
    from neutron.openstack.common import uuidutils
except ImportError:
    from oslo_utils import uuidutils

from vnc_api.vnc_api import IdPermsType, NoIdError
from vnc_api.vnc_api import InstanceIp, VirtualMachineInterface
from vnc_api.vnc_api import SecurityGroup
from vnc_api.vnc_api import Loadbalancer, LoadbalancerType

from .. resource_manager import ResourceManager
from .. import utils
import uuid

LOG = logging.getLogger(__name__)


class LoadbalancerManager(ResourceManager):
    _loadbalancer_type_mapping = {
        'vip_address': 'vip_address',
        'vip_subnet_id': 'vip_subnet_id',
        'admin_state': 'admin_state_up',
    }

    @property
    def property_type_mapping(self):
        return self._loadbalancer_type_mapping

    def make_properties(self, lb):
        props = LoadbalancerType()
        for key, mapping in self._loadbalancer_type_mapping.iteritems():
            if mapping in lb and lb[mapping] != attributes.ATTR_NOT_SPECIFIED:
                setattr(props, key, lb[mapping])
        return props

    def _get_listeners(self, lb):
        ll_list = []
        ll_back_refs = lb.get_loadbalancer_listener_back_refs()
        if ll_back_refs:
            for ll_back_ref in ll_back_refs:
                ll_list.append(ll_back_ref['uuid'])
        return ll_list

    def _get_interface_params(self, lb, props):
        vmi_list = lb.get_virtual_machine_interface_refs()
        if vmi_list is None:
            return None

        port_id = vmi_list[0]['uuid']
        if not props.vip_address or props.vip_address == attributes.ATTR_NOT_SPECIFIED:
            try:
                vmi = self._api.virtual_machine_interface_read(id=port_id)
            except NoIdError as ex:
                LOG.error(ex)
                return None

            ip_refs = vmi.get_instance_ip_back_refs()
            if ip_refs:
                try:
                    iip = self._api.instance_ip_read(id=ip_refs[0]['uuid'])
                except NoIdError as ex:
                    LOG.error(ex)
                    return None
                props.vip_address = iip.get_instance_ip_address()

        return port_id

    def make_dict(self, lb, fields=None):
        props = lb.get_loadbalancer_properties()
        port_id = self._get_interface_params(lb, props)
        res = {'id': lb.uuid,
               'tenant_id': lb.parent_uuid.replace('-', ''),
               'name': lb.display_name,
               'description': self._get_object_description(lb),
               'vip_port_id': port_id,
               'vip_subnet_id': props.vip_subnet_id,
               'vip_address': props.vip_address,
               'admin_state_up': props.admin_state,
               'listeners': self._get_listeners(lb)}

        return self._fields(res, fields)

    def resource_read(self, id):
        return self._api.loadbalancer_read(id=id)

    def resource_list(self, tenant_id=None):
        if tenant_id:
            parent_id = str(uuid.UUID(tenant_id))
        else:
            parent_id = None
        return self._api.loadbalancers_list(parent_id=parent_id)

    def resource_update(self, obj):
        return self._api.loadbalancer_update(obj)

    def resource_delete(self, id):
        return self._api.loadbalancer_delete(id=id)

    def get_exception_notfound(self, id=None):
        return loadbalancer.VipNotFound(vip_id=id)

    def get_exception_inuse(self, id=None):
        pass

    @property
    def neutron_name(self):
        return "loadbalancer"

    @property
    def resource_name_plural(self):
        return "loadbalancers"

    def _create_virtual_interface(self, project, lb_id, subnet_id,
                                  ip_address):
        network_id = utils.get_subnet_network_id(self._api, subnet_id)
        try:
            vnet = self._api.virtual_network_read(id=network_id)
        except NoIdError:
            raise n_exc.NetworkNotFound(net_id=network_id)

        vmi = VirtualMachineInterface(lb_id, project)
        vmi.set_virtual_network(vnet)
        vmi.set_virtual_machine_interface_device_owner(n_constants.DEVICE_OWNER_LOADBALANCER)

        sg_obj = SecurityGroup("default", project)
        vmi.add_security_group(sg_obj)
        self._api.virtual_machine_interface_create(vmi)

        iip_obj = InstanceIp(name=lb_id)
        iip_obj.set_virtual_network(vnet)
        iip_obj.set_virtual_machine_interface(vmi)
        if ip_address and ip_address != attributes.ATTR_NOT_SPECIFIED:
            iip_obj.set_instance_ip_address(ip_address)
        self._api.instance_ip_create(iip_obj)
        iip = self._api.instance_ip_read(id=iip_obj.uuid)
        vip_address = iip.get_instance_ip_address()

        return vmi, vip_address

    def _delete_virtual_interface(self, vmi_list):
        if vmi_list is None:
            return

        for vmi_ref in vmi_list:
            interface_id = vmi_ref['uuid']
            try:
                vmi = self._api.virtual_machine_interface_read(id=interface_id)
            except NoIdError as ex:
                LOG.error(ex)
                continue

            ip_refs = vmi.get_instance_ip_back_refs()
            if ip_refs:
                for ref in ip_refs:
                    self._api.instance_ip_delete(id=ref['uuid'])

            fip_refs = vmi.get_floating_ip_back_refs()
            for ref in fip_refs or []:
                try:
                    fip = self._api.floating_ip_read(id=ref['uuid'])
                except NoIdError as ex:
                    LOG.error(ex)
                    continue
                fip.set_virtual_machine_interface_list([])
                self._api.floating_ip_update(fip)

            self._api.virtual_machine_interface_delete(id=interface_id)

    def create(self, context, loadbalancer):
        """
        Create a loadbalancer.
        """
        l = loadbalancer['loadbalancer']
        tenant_id = self._get_tenant_id_for_create(context, l)
        project = self._project_read(project_id=tenant_id)

        obj_uuid = uuidutils.generate_uuid()
        name = self._get_resource_name('loadbalancer', project,
                                       l['name'], obj_uuid)
        id_perms = IdPermsType(enable=True, description=l['description'])
        lb = Loadbalancer(name, project, id_perms=id_perms,
                          display_name=l['name'])
        lb.uuid = obj_uuid

        vmi, vip_address = self._create_virtual_interface(project,
            obj_uuid, l['vip_subnet_id'], l.get('vip_address'))
        lb.set_virtual_machine_interface(vmi)

        props = self.make_properties(l)
        props.set_vip_address(vip_address)
        lb.set_loadbalancer_properties(props)
        self._api.loadbalancer_create(lb)

        return self.make_dict(lb)

    def delete(self, context, id):
        try:
            lb = self._api.loadbalancer_read(id=id)
        except NoIdError:
            loadbalancer.EntityNotFound(id=id)

        super(LoadbalancerManager, self).delete(context, id)
        self._delete_virtual_interface(
            lb.get_virtual_machine_interface_refs())

    def _update_loadbalancer_properties(self, props, id, lb):
        """
        Update loadbalancer properties and return True if the have been
        modified
        """
        # according to the spec:
        # vip_address, vip_subnet_id are immutable
        immutable = ['vip_address', 'vip_subnet_id']
        for field in immutable:
            if field not in lb:
                continue
            if getattr(props, field) != lb[field]:
                msg = 'Attribute %s in loadbalancer %s is immutable' % (field, id)
                raise n_exc.BadRequest(resource='loadbalancer', msg=msg)

        # update
        change = self.update_properties_subr(props, lb)
        return change

    def update_properties(self, lb_db, id, lb):
        props = lb_db.get_loadbalancer_properties()
        if self._update_loadbalancer_properties(props, id, lb):
            lb_db.set_loadbalancer_properties(props)
            return True
        return False
