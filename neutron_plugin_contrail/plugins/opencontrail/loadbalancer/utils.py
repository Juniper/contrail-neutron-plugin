try:
    from neutron.common.exceptions import SubnetNotFound
except ImportError:
    from neutron_lib.exceptions import SubnetNotFound
from cfgm_common import exceptions as vnc_exc


def get_subnet_network_id(client, subnet_id):
    try:
        kv_pair = client.kv_retrieve(subnet_id)
    except vnc_exc.NoIdError:
        raise SubnetNotFound(subnet_id=subnet_id)
    return kv_pair.split()[0]


def get_subnet_cidr(client, subnet_id):
    try:
        kv_pair = client.kv_retrieve(subnet_id)
    except vnc_exc.NoIdError:
        raise SubnetNotFound(subnet_id=subnet_id)
    return kv_pair.split()[1]
