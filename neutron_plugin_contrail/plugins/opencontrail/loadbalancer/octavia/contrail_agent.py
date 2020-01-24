#
# Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
#

import time

from oslo_log import log as logging

LOG = logging.getLogger(__name__)

def test_agent(exit_event):
    LOG.debug("contrail-agent init")
    while True:
        time.sleep(2)
        LOG.debug("processing!!")
        if exit_event.is_set():
                return
