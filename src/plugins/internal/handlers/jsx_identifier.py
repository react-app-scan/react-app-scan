from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
import time
# function is higher than block
# a little bit risky to use handle prop
# should be fine
from src.plugins.handler import Handler
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge


class HandleJSXIdentifier(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_identifier(self.G, self.node_id, self.extra)
        return r


def ast_jsx_identifier(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    node_attr = G.get_node_attr(ast_node)
    node_name = node_attr['code']

    loggers.main_logger.log(ATTENTION, 'JSX Identifier {}, name {}, extra'.format(ast_node, node_name, extra))

    # We do nothing in the jsx_identifier handler since we've already added the component node in the "jsx_element" handler.

    return NodeHandleResult()
