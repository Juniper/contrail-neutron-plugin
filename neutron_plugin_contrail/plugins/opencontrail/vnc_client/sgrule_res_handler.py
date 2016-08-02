#  Copyright 2015.  All rights reserved.
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

import uuid

from cfgm_common import exceptions as vnc_exc
from neutron.common import constants
from vnc_api import vnc_api

import contrail_res_handler as res_handler
import sg_res_handler as sg_handler


class SecurityGroupRuleMixin(object):
    def _security_group_rule_vnc_to_neutron(self, sg_id, sg_rule,
                                            sg_obj=None, fields=None):
        sgr_q_dict = {}
        if sg_id is None:
            return sgr_q_dict

        if not sg_obj:
            try:
                sg_obj = sg_handler.SecurityGroupHandler(
                    self._vnc_lib).get_sg_obj(id=sg_id)
            except vnc_exc.NoIdError:
                self._raise_contrail_exception(
                    'SecurityGroupNotFound',
                    id=sg_id, resource='security_group_rule')

        remote_cidr = None
        remote_sg_uuid = None
        saddr = sg_rule.get_src_addresses()[0]
        daddr = sg_rule.get_dst_addresses()[0]
        if saddr.get_security_group() == 'local':
            direction = 'egress'
            addr = daddr
        elif daddr.get_security_group() == 'local':
            direction = 'ingress'
            addr = saddr
        else:
            self._raise_contrail_exception(
                'SecurityGroupRuleNotFound',
                id=sg_rule.get_rule_uuid(), resource='security_group_rule')

        if addr.get_subnet():
            remote_cidr = '%s/%s' % (addr.get_subnet().get_ip_prefix(),
                                     addr.get_subnet().get_ip_prefix_len())
        elif addr.get_security_group():
            if addr.get_security_group() != 'any' and (
                    addr.get_security_group() != 'local'):
                remote_sg = addr.get_security_group()
                if remote_sg != ':'.join(sg_obj.get_fq_name()):
                    try:
                        remote_sg_uuid = self._vnc_lib.fq_name_to_id(
                            'security-group', remote_sg.split(':'))
                    except vnc_exc.NoIdError:
                        # Filter rule out as the remote security group does not
                        # exist anymore
                        return sgr_q_dict
                else:
                    remote_sg_uuid = sg_obj.uuid

        sgr_q_dict['id'] = sg_rule.get_rule_uuid()
        sgr_q_dict['tenant_id'] = self._project_id_vnc_to_neutron(
            sg_obj.parent_uuid)
        sgr_q_dict['security_group_id'] = sg_obj.uuid
        if hasattr(sg_rule, 'get_ethertype'):
            sgr_q_dict['ethertype'] = sg_rule.get_ethertype()
        else:
            sgr_q_dict['ethertype'] = 'IPv4'
        sgr_q_dict['direction'] = direction
        proto = sg_rule.get_protocol()
        sgr_q_dict['protocol'] = None if proto == 'any' else proto
        port_min = sg_rule.get_dst_ports()[0].get_start_port()
        if sgr_q_dict['protocol'] in (constants.PROTO_NAME_ICMP,
                                      str(constants.PROTO_NUM_ICMP)):
            sgr_q_dict['port_range_min'] = port_min
        else:
            sgr_q_dict['port_range_min'] = None if port_min == 0 else port_min
        port_max = (sg_rule.get_dst_ports()[0].get_end_port())
        sgr_q_dict['port_range_max'] = None if port_max == 65535 else port_max
        sgr_q_dict['remote_ip_prefix'] = remote_cidr
        sgr_q_dict['remote_group_id'] = remote_sg_uuid

        if fields:
            sgr_q_dict = self._filter_res_dict(sgr_q_dict, fields)
        return sgr_q_dict
    # end _security_group_rule_vnc_to_neutron

    def _security_group_rule_find(self, sgr_id, project_uuid=None):
        dom_projects = []
        if not project_uuid:
            dom_projects = self._project_list_domain(None)
        else:
            dom_projects = [{'uuid': project_uuid}]

        for project in dom_projects:
            proj_id = project['uuid']
            project_sgs = sg_handler.SecurityGroupHandler(
                self._vnc_lib).resource_list_by_project(proj_id)

            for sg_obj in project_sgs:
                sgr_entries = sg_obj.get_security_group_entries()
                if sgr_entries is None:
                    continue

                for sg_rule in sgr_entries.get_policy_rule():
                    if sg_rule.get_rule_uuid() == sgr_id:
                        return sg_obj, sg_rule

        return None, None
    # end _security_group_rule_find


class SecurityGroupRuleGetHandler(res_handler.ResourceGetHandler,
                                  SecurityGroupRuleMixin):
    def resource_get(self, context, sgr_id, fields=None):
        project_uuid = None
        if not context['is_admin']:
            project_uuid = self._project_id_neutron_to_vnc(context['tenant'])

        sg_obj, sg_rule = self._security_group_rule_find(sgr_id, project_uuid)
        if sg_obj and sg_rule:
            sgr_info = self._security_group_rule_vnc_to_neutron(sg_obj.uuid,
                                                                sg_rule, sg_obj,
                                                                fields=fields)
            if sgr_info:
                return sgr_info

        self._raise_contrail_exception('SecurityGroupRuleNotFound', id=sgr_id,
                                       resource='security_group_rule')

    def security_group_rules_read(self, sg_obj, fields=None, filters=None):
        sgr_entries = sg_obj.get_security_group_entries()
        sg_rules = []
        if sgr_entries is None:
            return

        if filters:
            filter_ids  = [id for id in filters.get('id', []) if filters]
        else:
            filter_ids = None
        for sg_rule in sgr_entries.get_policy_rule():
            if filter_ids and sg_rule.get_rule_uuid() not in filter_ids:
                continue

            sgr_info = self._security_group_rule_vnc_to_neutron(sg_obj.uuid,
                                                                sg_rule,
                                                                sg_obj,
                                                                fields=fields)
            if sgr_info:
                sg_rules.append(sgr_info)

        return sg_rules
    # end security_group_rules_read

    def resource_list(self, context, filters=None, fields=None):
        ret_list = []

        # collect phase
        all_sgs = []
        if filters and 'tenant_id' in filters:
            project_ids = self._validate_project_ids(context,
                                                     filters['tenant_id'])
            for p_id in project_ids:
                project_sgs = sg_handler.SecurityGroupHandler(
                    self._vnc_lib).resource_list_by_project(p_id)

                all_sgs.append(project_sgs)
        else:  # no filters
            p_id = None
            if context and not context['is_admin']:
                p_id = self._project_id_neutron_to_vnc(context['tenant'])
            project_sgs = sg_handler.SecurityGroupHandler(
                self._vnc_lib).resource_list_by_project(p_id)

            all_sgs.append(project_sgs)

        # prune phase
        for project_sgs in all_sgs:
            for sg_obj in project_sgs:
                # TODO() implement same for name specified in filter
                sgr_info = self.security_group_rules_read(sg_obj,
                                                          fields=fields,
                                                          filters=filters)
                if sgr_info:
                    ret_list.extend(sgr_info)

        return ret_list


class SecurityGroupRuleDeleteHandler(res_handler.ResourceDeleteHandler,
                                     SecurityGroupRuleMixin):
    def _security_group_rule_delete(self, sg_obj, sg_rule):
        rules = sg_obj.get_security_group_entries()
        rules.get_policy_rule().remove(sg_rule)
        sg_obj.set_security_group_entries(rules)
        sg_handler.SecurityGroupHandler(
            self._vnc_lib).resource_update_obj(sg_obj)
        return
    # end _security_group_rule_delete

    def resource_delete(self, context, sgr_id):
        project_uuid = None
        if not context['is_admin']:
            project_uuid = self._project_id_neutron_to_vnc(context['tenant'])

        sg_obj, sg_rule = self._security_group_rule_find(sgr_id, project_uuid)
        if sg_obj and sg_rule:
            return self._security_group_rule_delete(sg_obj, sg_rule)

        self._raise_contrail_exception('SecurityGroupRuleNotFound', id=sgr_id,
                                       resource='security_group_rule')


class SecurityGroupRuleCreateHandler(res_handler.ResourceCreateHandler,
                                     SecurityGroupRuleMixin):
    resource_create_method = "security_group_rule_create"

    def _convert_protocol(self, value):
        IP_PROTOCOL_MAP = {constants.PROTO_NUM_TCP: constants.PROTO_NAME_TCP,
                           constants.PROTO_NUM_UDP: constants.PROTO_NAME_UDP,
                           constants.PROTO_NUM_ICMP: constants.PROTO_NAME_ICMP}

        if value is None:
            return

        if isinstance(value, str) and value.lower() == 'any':
            return 'any'
        try:
            val = int(value)
            # TODO(ethuleau): support all protocol numbers
            if val >= 0 and val <= 255:
                return IP_PROTOCOL_MAP[val] if val in IP_PROTOCOL_MAP else (
                    str(val))
            self._raise_contrail_exception(
                'SecurityGroupRuleInvalidProtocol',
                protocol=value, values=IP_PROTOCOL_MAP.values(),
                resource='security_group_rule')
        except (ValueError, TypeError):
            if value.lower() in IP_PROTOCOL_MAP.values():
                return value.lower()
            self._raise_contrail_exception(
                'SecurityGroupRuleInvalidProtocol',
                protocol=value, values=IP_PROTOCOL_MAP.values(),
                resource='security_group_rule')

    def _validate_port_range(self, rule):
        """Check that port_range is valid."""
        if (rule['port_range_min'] is None and
                rule['port_range_max'] is None):
            return
        if not rule['protocol']:
            self._raise_contrail_exception(
                'SecurityGroupProtocolRequiredWithPorts',
                resource='security_group_rule')
        if rule['protocol'] in [constants.PROTO_NAME_TCP,
                                constants.PROTO_NAME_UDP]:
            if (rule['port_range_min'] is not None and
                    rule['port_range_min'] <= rule['port_range_max']):
                pass
            else:
                self._raise_contrail_exception(
                    'SecurityGroupInvalidPortRange',
                    resource='security_group_rule')
        elif rule['protocol'] == constants.PROTO_NAME_ICMP:
            for attr, field in [('port_range_min', 'type'),
                                ('port_range_max', 'code')]:
                if rule[attr] > 255:
                    self._raise_contrail_exception(
                        'SecurityGroupInvalidIcmpValue', field=field,
                        attr=attr, value=rule[attr],
                        resource='security_group_rule')
            if (rule['port_range_min'] is None and
                    rule['port_range_max']):
                self._raise_contrail_exception(
                    'SecurityGroupMissingIcmpType',
                    value=rule['port_range_max'],
                    resource='security_group_rule')

    def _security_group_rule_neutron_to_vnc(self, sgr_q):
        # default port values
        if sgr_q['protocol'] in (constants.PROTO_NAME_ICMP,
                                 str(constants.PROTO_NUM_ICMP)):
            port_min = None
            port_max = None
        else:
            port_min = 0
            port_max = 65535

        if sgr_q['port_range_min'] is not None:
            port_min = sgr_q['port_range_min']
        if sgr_q['port_range_max'] is not None:
            port_max = sgr_q['port_range_max']

        if sgr_q['remote_ip_prefix'] and sgr_q['remote_group_id']:
            self._raise_contrail_exception("BadRequest",
                                           msg="Can't set remote_ip_prefix with remote_group_id",
                                           resource="security_group_rule")

        endpt = [vnc_api.AddressType(security_group='any')]
        if sgr_q['remote_ip_prefix']:
            cidr = sgr_q['remote_ip_prefix'].split('/')
            pfx = cidr[0]
            pfx_len = int(cidr[1])
            endpt = [vnc_api.AddressType(
                subnet=vnc_api.SubnetType(pfx, pfx_len))]
        elif sgr_q['remote_group_id']:
            try:
                sg_obj = sg_handler.SecurityGroupHandler(
                    self._vnc_lib).get_sg_obj(id=sgr_q['remote_group_id'])
            except vnc_exc.NoIdError:
                self._raise_contrail_exception('SecurityGroupNotFound',
                                               id=sgr_q['remote_group_id'],
                                               resource='security_group_rule')

            if sgr_q.get('tenant_id') and (
                    sg_obj.parent_uuid != self._project_id_neutron_to_vnc(sgr_q['tenant_id'])):
                self._raise_contrail_exception("NotFound")

            endpt = [vnc_api.AddressType(
                security_group=sg_obj.get_fq_name_str())]

        if sgr_q['direction'] == 'ingress':
            dir = '>'
            local = endpt
            remote = [vnc_api.AddressType(security_group='local')]
        else:
            dir = '>'
            remote = endpt
            local = [vnc_api.AddressType(security_group='local')]

        if not sgr_q['protocol']:
            sgr_q['protocol'] = 'any'

        if not sgr_q['remote_ip_prefix'] and not sgr_q['remote_group_id']:
            if not sgr_q['ethertype']:
                sgr_q['ethertype'] = 'IPv4'

        sgr_uuid = str(uuid.uuid4()) if 'id' not in sgr_q else sgr_q['id']

        rule = vnc_api.PolicyRuleType(
            rule_uuid=sgr_uuid, direction=dir,
            protocol=sgr_q['protocol'],
            src_addresses=local,
            src_ports=[vnc_api.PortType(0, 65535)],
            dst_addresses=remote,
            dst_ports=[vnc_api.PortType(port_min, port_max)],
            ethertype=sgr_q['ethertype'])
        return rule
    # end _security_group_rule_neutron_to_vnc

    def _security_group_rule_create(self, sg_id, sg_rule, project_id):
        sghandler = sg_handler.SecurityGroupHandler(self._vnc_lib)
        try:
            sg_vnc = sghandler.get_sg_obj(id=sg_id)
        except vnc_exc.NoIdError:
            self._raise_contrail_exception('SecurityGroupNotFound', id=sg_id,
                                           resource='security_group')

        if project_id and sg_vnc.parent_uuid != self._project_id_neutron_to_vnc(project_id):
            self._raise_contrail_exception('NotFound')
        rules = sg_vnc.get_security_group_entries()
        if rules is None:
            rules = vnc_api.PolicyEntriesType([sg_rule])
        else:
            rules.add_policy_rule(sg_rule)

        sg_vnc.set_security_group_entries(rules)
        try:
            sghandler.resource_update_obj(sg_vnc)
        except vnc_exc.PermissionDenied as e:
            self._raise_contrail_exception(
                'BadRequest',
                resource='security_group_rule', msg=str(e))
        except vnc_exc.BadRequest as e:
            self._raise_contrail_exception(
                'BadRequest',
                resource='security_group_rule', msg=str(e.content))
        except vnc_exc.RefsExistError as e:
            try:
                rule_uuid = str(e).split(':')[1].strip()
            except IndexError:
                rule_uuid = None
            self._raise_contrail_exception('SecurityGroupRuleExists',
                                           resource='security_group_rule',
                                           id=rule_uuid)
        return
    # end _security_group_rule_create

    def resource_create(self, context, sgr_q):
        sgr_q['protocol'] = self._convert_protocol(sgr_q['protocol'])
        self._validate_port_range(sgr_q)
        sg_id = sgr_q['security_group_id']
        sg_rule = self._security_group_rule_neutron_to_vnc(sgr_q)
        self._security_group_rule_create(sg_id, sg_rule,
                                         sgr_q.get('tenant_id', None))
        ret_sg_rule_q = self._security_group_rule_vnc_to_neutron(sg_id,
                                                                 sg_rule)

        return ret_sg_rule_q


class SecurityGroupRuleHandler(SecurityGroupRuleGetHandler,
                               SecurityGroupRuleDeleteHandler,
                               SecurityGroupRuleCreateHandler):
    pass
