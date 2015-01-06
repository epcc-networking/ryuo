def get_level(link, level):
    return level[link.src.dpid] - level[link.dst.dpid]


def compare_link(l1, l2, level, degree, in_port, candidate_sinks,
                 in_port_sink):
    if l1.src.port_no == in_port:
        return 1
    if l2.src.port_no == in_port:
        return -1
    level_diff = level[l1.dst.dpid] - level[l2.dst.dpid]
    if level_diff != 0:
        return level_diff
    if candidate_sinks[l2] == in_port_sink:
        return -1
    if candidate_sinks[l1] == in_port_sink:
        return 1
    return degree[l2.dst.dpid] - degree[l1.dst.dpid]
