#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid
import thread
import functools

from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as o_exc
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.api.drivers.data_models import UnsetType
from octavia_lib.common import constants as o_const

from oslo_config import cfg
from oslo_log import log as logging

from neutron_plugin_contrail.common import utils as contrail_utils
from neutron_plugin_contrail.services.loadbalancer import utils as lb_utils
from neutron_plugin_contrail.services.loadbalancer.octavia import constants \
    as c_const
from vnc_api import exceptions as vnc_exc
from vnc_api.vnc_api import InstanceIp, VirtualMachineInterface, SecurityGroup
from vnc_api.vnc_api import Loadbalancer, LoadbalancerType
from vnc_api.vnc_api import LoadbalancerListener, LoadbalancerListenerType
from vnc_api.vnc_api import LoadbalancerPool, LoadbalancerPoolType
from vnc_api.vnc_api import IdPermsType

try:
    from neutron.common.constants import DEVICE_OWNER_LOADBALANCER
except Exception:
    from neutron_lib.constants import DEVICE_OWNER_LOADBALANCER


CONF = cfg.CONF
LOG = logging.getLogger(__name__)

PROVIDER = "opencontrail"
SAS_FQ_NAME = ["default-global-system-config", PROVIDER]


def check_opts(unsupported_opts, func_type):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                if func_type == c_const.UPDATE_RES:
                    obj = args[2]
                elif func_type == c_const.CREATE_RES:
                    obj = args[1]
                else:
                    msg = "check_opts decorator applied to unknown func type"
                    raise o_exc.DriverError(user_fault_string=msg,
                                            operator_fault_string=msg)
            except IndexError as e:
                msg = str(e)
                raise o_exc.DriverError(user_fault_string=msg,
                                        operator_fault_string=msg)

            error_opts = []
            for opt in unsupported_opts:
                attr = getattr(obj, opt, None)
                if attr and not isinstance(attr, UnsetType):
                    error_opts.append(opt)

            if error_opts:
                msg = "Contrail Driver doesn't support the following "\
                      "options: %s" % ", ".join(error_opts)
                raise o_exc.DriverError(user_fault_string=msg,
                                        operator_fault_string=msg)
            return func(*args, **kwargs)
        return wrapper
    return decorator


class ContrailProviderDriver(driver_base.ProviderDriver):

    def __init__(self):
        super(ContrailProviderDriver, self).__init__()
        contrail_utils.register_vnc_api_options()
        self._api = contrail_utils.get_vnc_api_instance()

        self._driver_lib = driver_lib.DriverLibrary(
            status_socket=CONF.driver_agent.status_socket_path,
            stats_socket=CONF.driver_agent.stats_socket_path)

    def update_status(self, status):
        """ updates status of loadbalancer resources
        """
        thread.start_new_thread(self._driver_lib.update_loadbalancer_status,
                                (status,))

    def raise_error(self, msg):
        raise o_exc.DriverError(user_fault_string=msg,
                                operator_fault_string=msg)

    def read_project(self, project_id):
        """ read project from contrail api
        """
        # add dashes to project uuid
        project_id = str(uuid.UUID(project_id))

        try:
            return self._api.project_read(id=str(uuid.UUID(project_id)))
        except vnc_exc.NoIdError:
            self.raise_error("Project ID %s not found" % project_id)

    def get_fq_name(self, project_id, resource_id):
        project = self.read_project(project_id)
        fq_name = list(project.fq_name)
        fq_name.append(resource_id)
        return fq_name

    @check_opts(c_const.unsupported_loadbalancer_opts, c_const.CREATE_RES)
    def loadbalancer_create(self, lb):
        """ creates a load balancer
        """
        project = self.read_project(lb.project_id)

        try:
            sas_obj = self._api.service_appliance_set_read(fq_name=SAS_FQ_NAME)
        except vnc_exc.NoIdError:
            msg = "Service Appliance Set not found: %s" % SAS_FQ_NAME
            self.raise_error(msg)

        id_perms = IdPermsType(enable=True, description=lb.description)

        contrail_lb = Loadbalancer(name=lb.loadbalancer_id,
                                   parent_obj=project,
                                   uuid=lb.loadbalancer_id,
                                   loadbalancer_provider=PROVIDER,
                                   id_perms=id_perms,
                                   display_name=lb.name)
        contrail_lb.set_service_appliance_set(sas_obj)

        props = LoadbalancerType(provisioning_status=o_const.ACTIVE,
                                 operating_status=o_const.ONLINE,
                                 vip_subnet_id=lb.vip_subnet_id,
                                 vip_address=lb.vip_address,
                                 admin_state=lb.admin_state_up)

        contrail_lb.set_loadbalancer_properties(props)

        try:
            self._api.loadbalancer_create(contrail_lb)
        except vnc_exc.RefsExistError as e:
            self.raise_error(msg=str(e))

        status = {
            o_const.LOADBALANCERS: [{
                o_const.ID: lb.loadbalancer_id,
                o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                o_const.OPERATING_STATUS: o_const.ONLINE
            }]
        }
        self.update_status(status)

    def loadbalancer_delete(self, lb, cascade=False):
        """Deletes a load balancer
        """
        if cascade:
            self.raise_error(
                msg="Contrail driver doesn't support cascade deletion")

        try:
            vmi = self._api.virtual_machine_interface_read(id=lb.vip_port_id)
            ip_refs = vmi.get_instance_ip_back_refs()
            if ip_refs:
                for ref in ip_refs:
                    self._api.instance_ip_delete(id=ref['uuid'])

            fip_refs = vmi.get_floating_ip_back_refs()
            if fip_refs:
                for ref in fip_refs:
                    fip = self._api.floating_ip_read(id=ref['uuid'])
                    fip.set_virtual_machine_interface_list([])
                    self._api.floating_ip_update(fip)

            lb_fq_name = self.get_fq_name(lb.project_id, lb.loadbalancer_id)
            self._api.loadbalancer_delete(fq_name=lb_fq_name)
            self._api.virtual_machine_interface_delete(id=lb.vip_port_id)
        except Exception as e:
            self.raise_error(msg=str(e))


        status = {
            o_const.LOADBALANCERS: [{
                o_const.ID: lb.loadbalancer_id,
                o_const.PROVISIONING_STATUS: o_const.DELETED,
                o_const.OPERATING_STATUS: o_const.OFFLINE
            }]
        }

        self.update_status(status)


    def is_updated(self, old_res, updated_opts):
        for opt, val in updated_opts.items():
            if getattr(old_res, opt) != val:
                return True
        return False


    def set_properties(self, res, res_type, props, opts):

        attr_mapping = c_const.RESOURCE_INFO[res_type][c_const.ATTR_MAP]
        for octavia_attr, val in opts.items():
            if octavia_attr in attr_mapping:
                contrail_attr = attr_mapping[octavia_attr]
                setattr(props, contrail_attr, val)

        props_setter_name = c_const.RESOURCE_INFO[res_type][c_const.SET_PROPS]
        setter_method = getattr(res, props_setter_name)
        setter_method(props)


    def update_resource(self, old_obj, new_obj, res_type, res_id, proj_id):

        try:
            updated_opts = new_obj.to_dict(render_unsets=False)

            for field in c_const.immutable_fields:
                updated_opts.pop(field, None)

            if not self.is_updated(old_obj, updated_opts):
                return

            fq_name = self.get_fq_name(proj_id, res_id)
            LOG.debug("%s" % fq_name)

            res = self._api._object_read(res_type, fq_name=fq_name)

            if o_const.NAME in updated_opts:
                res.set_display_name(updated_opts[o_const.NAME])
                updated_opts.pop(o_const.NAME, None)

            if o_const.DESCRIPTION in updated_opts:
                id_perms = res.get_id_perms()
                id_perms.set_description(updated_opts[o_const.DESCRIPTION])
                res.set_id_perms(id_perms)
                updated_opts.pop(o_const.DESCRIPTION, None)

            if updated_opts:
		props_getter_name = c_const.RESOURCE_INFO[res_type][c_const.GET_PROPS]
		getter_method = getattr(res, props_getter_name)
		properties = getter_method()
                self.set_properties(res, res_type, properties, updated_opts)

            self._api._object_update(res_type, res)
        except Exception as e:
            self.raise_error(str(e))

    @check_opts(c_const.unsupported_loadbalancer_opts, c_const.UPDATE_RES)
    def loadbalancer_update(self, old_lb, new_lb):
        """Updates a load balancer
        """
        self.update_resource(old_lb, new_lb, c_const.LOADBALANCER_TYPE,
                             old_lb.loadbalancer_id, old_lb.project_id)

        status = {
            o_const.LOADBALANCERS: [{
                o_const.ID: new_lb.loadbalancer_id,
                o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                o_const.OPERATING_STATUS: o_const.ONLINE
            }]
        }
        self.update_status(status)

    def create_vip_port(self, lb_id, project_id, vip_dict):
        """Creates a port for loadbalancer VIP
        """
        try:
            project = self.read_project(project_id)
            vnet = lb_utils.get_vnet_obj(self._api, vip_dict['vip_network_id'])

            iip_obj = InstanceIp(name=lb_id)
            iip_obj.set_subnet_uuid(vip_dict['vip_subnet_id'])

            vmi = VirtualMachineInterface(lb_id, project)
            vmi.set_virtual_network(vnet)
            vmi.set_virtual_machine_interface_device_owner(
                DEVICE_OWNER_LOADBALANCER)

            sg_obj = SecurityGroup("default", project)
            vmi.add_security_group(sg_obj)
            self._api.virtual_machine_interface_create(vmi)

            iip_obj.set_virtual_network(vnet)
            iip_obj.set_virtual_machine_interface(vmi)

            if 'vip_address' in vip_dict and vip_dict['vip_address'] is not None:
                iip_obj.set_instance_ip_address(ip_address)

            self._api.instance_ip_create(iip_obj)
            iip = self._api.instance_ip_read(id=iip_obj.uuid)
            vip_address = iip.get_instance_ip_address()

            vip_dict['vip_address'] = vip_address
            vip_dict['vip_port_id'] = vmi.get_uuid()

            return vip_dict
        except Exception as e:
            self.raise_error(msg=str(e))

    @check_opts(c_const.unsupported_listener_opts, c_const.CREATE_RES)
    def listener_create(self, listener):
        """Creates a new listener.
        """
        try:
            octavia_lb = self._driver_lib.get_loadbalancer(
                listener.loadbalancer_id)
            project = self.read_project(octavia_lb.project_id)

            id_perms = IdPermsType(enable=True,
                                   description=listener.description)

            contrail_lis = LoadbalancerListener(name=listener.listener_id,
                                                parent_obj=project,
                                                uuid=listener.listener_id,
                                                id_perms=id_perms,
                                                display_name=listener.name)

            fq_name = list(project.fq_name)
            fq_name.append(listener.loadbalancer_id)
            contrail_lb = self._api.loadbalancer_read(fq_name=fq_name)
            contrail_lis.set_loadbalancer(contrail_lb)

            self.set_properties(contrail_lis,
                                c_const.LISTENER_TYPE,
                                LoadbalancerListenerType(),
                                listener.to_dict())

            self._api.loadbalancer_listener_create(contrail_lis)
            status = {
                o_const.LOADBALANCERS: [{
                    o_const.ID: listener.loadbalancer_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.LISTENERS: [{
                    o_const.ID: listener.listener_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }]
            }

            self.update_status(status)

        except Exception as e:
            self.raise_error(msg=str(e))


    @check_opts(c_const.unsupported_listener_opts, c_const.UPDATE_RES)
    def listener_update(self, old_listener, new_listener):
        """Updates a listener.
        """

        self.update_resource(old_listener, new_listener,
                             c_const.LISTENER_TYPE,
                             old_listener.listener_id,
                             old_listener.project_id)

        status = {
            o_const.LOADBALANCERS: [{
                o_const.ID: old_listener.loadbalancer_id,
                o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                o_const.OPERATING_STATUS: o_const.ONLINE
            }],
            o_const.LISTENERS: [{
                o_const.ID: new_listener.listener_id,
                o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                o_const.OPERATING_STATUS: o_const.ONLINE
            }]
        }
        self.update_status(status)


    def listener_delete(self, listener):
        """Deletes a listener.
        """
        try:
            fq_name = self.get_fq_name(listener.project_id,
                                       listener.listener_id)

            res = self._api.loadbalancer_listener_delete(fq_name=fq_name)

            status = {
                o_const.LOADBALANCERS: [{
                    o_const.ID: listener.loadbalancer_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.LISTENERS: [{
                    o_const.ID: listener.listener_id,
                    o_const.PROVISIONING_STATUS: o_const.DELETED,
                    o_const.OPERATING_STATUS: o_const.OFFLINE
                }]
            }
            self.update_status(status)
        except Exception as e:
            self.raise_error(str(e))

    def pool_create(self, pool):
        """Creates a new pool.
        """
        #TODO: set custom lb attributes supported by contrail
        try:
            project = self.read_project(pool.project_id)

            id_perms = IdPermsType(enable=True,
                                   description=pool.description)

            contrail_pool = LoadbalancerPool(name=pool.pool_id,
                                             parent_obj=project,
                                             uuid=pool.pool_id,
                                             id_perms=id_perms,
                                             display_name=pool.name)

            fq_name = list(project.fq_name)
            fq_name.append(pool.listener_id)
            listener = self._api.loadbalancer_listener_read(fq_name=fq_name)
            contrail_pool.set_loadbalancer_listener(listener)

            props_dict = pool.to_dict()
            if pool.session_persistence:
                props_dict.update(pool.session_persistence)

            self.set_properties(contrail_pool,
                                c_const.POOL_TYPE,
                                LoadbalancerPoolType(),
                                props_dict)

            self._api.loadbalancer_pool_create(contrail_pool)

            status = {
                o_const.LOADBALANCERS: [{
                    o_const.ID: pool.loadbalancer_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.LISTENERS: [{
                    o_const.ID: pool.listener_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.POOLS: [{
                    o_const.ID: pool.pool_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
		}],
            }
            self.update_status(status)
	except Exception as e:
            self.raise_error(str(e))

    def pool_delete(self, pool):
	"""Deletes a pool.
	"""
        try:
            fq_name = self.get_fq_name(pool.project_id, pool.pool_id)
            res = self._api.loadbalancer_pool_delete(fq_name=fq_name)

            status = {
                o_const.LOADBALANCERS: [{
                    o_const.ID: pool.loadbalancer_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.LISTENERS: [{
                    o_const.ID: pool.listener_id,
                    o_const.PROVISIONING_STATUS: o_const.ACTIVE,
                    o_const.OPERATING_STATUS: o_const.ONLINE
                }],
                o_const.POOLS: [{
                    o_const.ID: pool.pool_id,
                    o_const.PROVISIONING_STATUS: o_const.DELETED,
                    o_const.OPERATING_STATUS: o_const.OFFLINE
                }]
            }
            self.update_status(status)
        except Exception as e:
            self.raise_error(str(e))
