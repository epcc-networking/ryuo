from ryu.base import app_manager
from ryu.topology import event


def get_link(app):
    rep = app.send_request(event.EventLinkRequest(None))
    return rep.links


app_manager.require_app('ryuo.local.topology', api_style=True)