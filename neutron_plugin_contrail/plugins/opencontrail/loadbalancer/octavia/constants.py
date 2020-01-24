from octavia_lib.common import constants as o_const

immutable_fields = [o_const.HEALTHMONITOR_ID,
                    o_const.L7POLICY_ID,
                    o_const.L7RULE_ID,
                    o_const.LISTENER_ID,
                    o_const.LOADBALANCER_ID,
                    o_const.MEMBER_ID,
                    o_const.POOL_ID,
                    o_const.PROJECT_ID,
                    ]

unsupported_loadbalancer_opts = ["vip_qos_policy_id"]


unsupported_listener_opts = ["client_ca_tls_container_ref",
                             "client_crl_container_ref",
                             "default_pool_id",
                             "insert_headers",
                             "allowed_cidrs"]

loadbalancer_type_mapping = {
    "vip_address": "vip_address",
    "vip_subnet_id": "vip_subnet_id",
    "admin_state_up": "admin_state",
    "provisioning_status": "provisioning_status",
    "operating_status": "operating_status",
}

listener_type_mapping = {
    'protocol': 'protocol',
    'protocol_port': 'protocol_port',
    'admin_state_up': 'admin_state',
    'connection_limit': 'connection_limit',
    'default_tls_container_ref': 'default_tls_container',
    'sni_containers_refs': 'sni_containers',
}

pool_type_mapping = {
    'admin_state_up': 'admin_state',
    'protocol': 'protocol',
    'lb_algorithm': 'loadbalancer_method',
    'subnet_id': 'subnet_id',
    'type': 'session_persistence',
    'cookie_name': 'persistence_cookie_name'
}

CREATE_RES = "create"
UPDATE_RES = "update"

GET_PROPS = "props_getter"
SET_PROPS = "props_setter"

ATTR_MAP = "mapping"

LOADBALANCER_TYPE = "loadbalancer"
LISTENER_TYPE = "loadbalancer-listener"
POOL_TYPE = "loadbalancer-pool"

RESOURCE_INFO = {
    LOADBALANCER_TYPE: {
        GET_PROPS: "get_loadbalancer_properties",
        SET_PROPS: "set_loadbalancer_properties",
        ATTR_MAP: loadbalancer_type_mapping
    },
    LISTENER_TYPE: {
        GET_PROPS: "get_loadbalancer_listener_properties",
        SET_PROPS: "set_loadbalancer_listener_properties",
        ATTR_MAP: listener_type_mapping
    },
    POOL_TYPE: {
        GET_PROPS: "get_loadbalancer_pool_properties",
        SET_PROPS: "set_loadbalancer_pool_properties",
        ATTR_MAP: pool_type_mapping
    }
}
