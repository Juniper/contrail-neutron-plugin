from neutron.common import exceptions as exc

class OverQuota(exc.OverQuota):
    message = _("You have reached the limit on the number of %(resource)ss that you can create")

