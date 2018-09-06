from neutron_lib.db import constants as db_constant


IS_SHIM_EXTENSION = False
IS_STANDARD_ATTR_EXTENSION = False
NAME = "Dummy Extension"
ALIAS = 'dummy'
DESCRIPTION = "A dummy extension for test and demo"
UPDATED_TIMESTAMP = '2018-01-01T10:00:00-00:00'
API_PREFIX = '/' + ALIAS
RESOURCE_NAME = ALIAS
COLLECTION_NAME = ALIAS + 's'
RESOURCE_ATTRIBUTE_MAP = {
    COLLECTION_NAME: {
        'id': {'allow_post': False, 'allow_put': False,
               'validate': {'type:uuid': None},
               'is_filter': True,
               'is_visible': True},
        'name': {'allow_post': True, 'allow_put': True,
                 'default': '',
                 'validate': {'type:string': db_constant.NAME_FIELD_SIZE},
                 'is_visible': True,
                 'enforce_policy': True},
        'tenant_id': {'allow_post': True, 'allow_put': False,
                      'required_by_policy': True,
                      'is_visible': True},
    }
}
SUB_RESOURCE_ATTRIBUTE_MAP = {}
ACTION_MAP = {}
ACTION_STATUS = {}
REQUIRED_EXTENSIONS = []
OPTIONAL_EXTENSIONS = []
