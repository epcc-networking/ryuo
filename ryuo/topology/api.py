from ryu.base import app_manager
from ryu.topology import event


def get_link(app, dpid=None):
    rep = app.send_request(event.EventLinkRequest(dpid))
    return rep.switches


def get_all_link(app):
    return get_link(app)


app_manager.require_app('ryuo.topology.switch_local', api_style=True)