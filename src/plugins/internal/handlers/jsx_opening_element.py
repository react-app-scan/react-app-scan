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
from src.core.utils import get_random_hex, wildcard, undefined, BranchTag
from src.core.helpers import to_values
from src.plugins.handler import Handler
from itertools import chain
from . import file
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
import traceback as tb
from collections import defaultdict
from src.core.options import options


class HandleJSXOpeningElement(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_opening_element(self.G, self.node_id, self.extra)
        return r


def ast_jsx_opening_element(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    jsx_ast_child_nodes = G.get_ordered_ast_child_nodes(ast_node)

    for ast_child in jsx_ast_child_nodes:
        G.cur_stmt = ast_child
        loggers.main_logger.log(ATTENTION, 'Handling JSXOpeningElement {}, child {}'.format(ast_node, ast_child))
        internal_manager.dispatch_node(ast_child, ExtraInfo(extra))

    return NodeHandleResult()
