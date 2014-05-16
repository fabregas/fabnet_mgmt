
from ClusterShell.NodeSet import NodeSet

def parse_nodes(nodes_str):
    node_set = NodeSet(nodes_str)
    return list(node_set)
