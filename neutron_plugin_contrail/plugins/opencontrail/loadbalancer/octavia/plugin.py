#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import uuid
import thread

from octavia_lib.api.drivers import driver_lib
from octavia_lib.api.drivers import exceptions as o_exc
from octavia_lib.api.drivers import provider_base as driver_base
from octavia_lib.api.drivers.data_models import Unset
from octavia_lib.common import constants

from oslo_config import cfg
from oslo_log import log as logging

from neutron_plugin_contrail.common import utils as contrail_utils
from neutron_plugin_contrail.services.loadbalancer import utils as lb_utils

from vnc_api import exceptions as vnc_exc
from vnc_api.vnc_api import InstanceIp, VirtualMachineInterface, SecurityGroup
from vnc_api.vnc_api import Loadbalancer, LoadbalancerType
from vnc_api.vnc_api import IdPermsType

try:
    from neutron.common.constants import DEVICE_OWNER_LOADBALANCER
except Exception:
    from neutron_lib.constants import DEVICE_OWNER_LOADBALANCER

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

PROVIDER="opencontrail"
SAS_FQ_NAME=["default-global-system-config", PROVIDER]


class LoadBalancerOctaviaPluginV2(driver_base.ProviderDriver):

    def __init__(self):
        super(LoadBalancerOctaviaPluginV2, self).__init__()
	contrail_utils.register_vnc_api_options()
	self._api = contrail_utils.get_vnc_api_instance()

	self._octavia_driver_lib = driver_lib.DriverLibrary(
                status_socket=CONF.driver_agent.status_socket_path,
                stats_socket=CONF.driver_agent.stats_socket_path)


    def is_name_unique(self, resource, parent, name):
        fq_name = list(parent.fq_name)
        fq_name.append(name)
        try:
            self._api.fq_name_to_id(resource, fq_name)
        except vnc_exc.NoIdError:
            return True
	return False


    def update_status(self, status):
	""" updates status of loadbalancer resources
	"""
        thread.start_new_thread(self._octavia_driver_lib.update_loadbalancer_status, (status,))


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

    def loadbalancer_create(self, lb):
	""" creates a load balancer
	"""
        project = self.read_project(lb.project_id)

	if not self.is_name_unique('loadbalancer', project, lb.loadbalancer_id):
            self.raise_error("Loadbalancer with uuid %s already exists" % lb.loadbalancer_id)

	if lb.admin_state_up == Unset:
            lb.admin_state_up = True

	try:
            sas_obj = self._api.service_appliance_set_read(fq_name=SAS_FQ_NAME)
	except vnc_exc.NoIdError:
            self.raise_error("Service Appliance Set %s not found" % SAS_FQ_NAME)

	id_perms = IdPermsType(enable=True, description=lb.description)

	contrail_lb = Loadbalancer(name=lb.loadbalancer_id,
                                   parent_obj=project,
                                   uuid=str(lb.loadbalancer_id),
                                   loadbalancer_provider=PROVIDER,
                                   id_perms=id_perms,
                                   display_name=lb.name)
	contrail_lb.set_service_appliance_set(sas_obj)

	props = LoadbalancerType(provisioning_status="ACTIVE",
                                 operating_status="ONLINE",
                                 vip_subnet_id=lb.vip_subnet_id,
                                 vip_address=lb.vip_address,
                                 admin_state=lb.admin_state_up)

	contrail_lb.set_loadbalancer_properties(props)

	try:
            self._api.loadbalancer_create(contrail_lb)
	except vnc_exc.RefsExistError as e:
            self.raise_error(msg=str(e))

        status = {'loadbalancers': [{"id": lb.loadbalancer_id,
                                     "provisioning_status": "ACTIVE",
                                     "operating_status": "ONLINE"}]}
	self.update_status(status)


    def loadbalancer_delete(self, lb, cascade=False):
        """Deletes a load balancer
	"""
	if cascade:
            self.raise_error(msg="Contrail driver doesn't support cascade deletion")

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

            project = self.read_project(lb.project_id)
            fq_name = list(project.fq_name)
            fq_name.append(lb.loadbalancer_id)
            self._api.loadbalancer_delete(fq_name=fq_name)
            self._api.virtual_machine_interface_delete(id=lb.vip_port_id)
        except Exception as e:
            self.raise_error(msg=str(e))

        status = {'loadbalancers': [{"id": lb.loadbalancer_id,
                                     "provisioning_status": "DELETED",
                                     "operating_status": "OFFLINE"}]}
        self.update_status(status)

    def _is_updated(self, old_lb, new_lb, option):
        new_attr = getattr(new_lb, option)
        old_attr = getattr(old_lb, option)

	if new_attr != Unset and new_attr != old_attr:
            return True

	return False

    def loadbalancer_update(self, old_lb, new_lb):
	"""Updates a load balancer
	"""
	unsupported_options = ["admin_state_up", "vip_qos_policy_id"]
	for opt in unsupported_options:
            if self._is_updated(old_lb, new_lb, opt):
                self.raise_error("Contrail provider does not support updating option: %s" % opt)

	update_options = {"name": False, "description": False}
	updated = False
	for opt in update_options.keys():
            if self._is_updated(old_lb, new_lb, opt):
		update_options[opt] = True
		updated = True

        if updated:
            project = self.read_project(old_lb.project_id)
            fq_name = list(project.fq_name)
            fq_name.append(old_lb.loadbalancer_id)

            try:
                contrail_lb_id = self._api.fq_name_to_id("loadbalancer", fq_name)
                lb = self._api.loadbalancer_read(id=contrail_lb_id)

                if update_options["name"]:
                    lb.set_display_name(new_lb.name)

                if update_options["description"]:
                    id_perms = lb.get_id_perms()
                    id_perms.set_description(new_lb.description)

                self._api.loadbalancer_update(lb)
            except Exception as e:
                self.raise_error(str(e))

        status = {'loadbalancers': [{"id": new_lb.loadbalancer_id,
                                     "provisioning_status": "ACTIVE",
                                     "operating_status": "ONLINE"}]}
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
