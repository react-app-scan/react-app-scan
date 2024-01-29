from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
from src.core.esprima import esprima_search, esprima_parse
from src.core.checker import traceback, vul_checking
from src.core.garbage_collection import cleanup_scope
from src.core.options import options
import time
# function is higher than block
# a little bit risky to use handle prop
# should be fine
from . import vars
from . import property
from src.plugins.handler import Handler


class HandleJSXChildren(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_children(self.G, self.node_id, self.extra)
        return r


def ast_jsx_children(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    jsx_children_ast_nodes = G.get_ordered_ast_child_nodes(ast_node)

    loggers.main_logger.log(ATTENTION, 'handling JSXChildren {}, children {}, extra {}'.format(ast_node, jsx_children_ast_nodes, extra))

    for ast_child in jsx_children_ast_nodes:
        internal_manager.dispatch_node(ast_child, extra=extra)

    return NodeHandleResult()
