from . import auth, groups, hub, proxy, service_activity, services, shares, users
from .base import *  # noqa

default_handlers = []
for mod in (auth, hub, proxy, users, groups, services, shares, service_activity):
    default_handlers.extend(mod.default_handlers)
