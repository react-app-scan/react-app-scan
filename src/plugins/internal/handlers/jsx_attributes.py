from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
from src.core.esprima import esprima_search, esprima_parse
from src.core.checker import traceback, vul_checking
from src.core.garbage_collection import cleanup_scope
from . import vars
from . import property
from src.plugins.handler import Handler
from itertools import chain
from . import file
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
import traceback as tb
from collections import defaultdict
from src.core.options import options


class HandleJSXAttributes(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_attributes(self.G, self.node_id, self.extra)
        return r


def ast_jsx_attributes(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    # jsx_attributes_children_ast_list = G.get_ordered_ast_child_nodes(ast_node)
    # loggers.main_logger.log(ATTENTION, 'Handling JSX Attributes {}, children {}'.format(ast_node, jsx_attributes_children_ast_list))

    # for ast_child in jsx_attributes_children_ast_list:
    #     internal_manager.dispatch_node(ast_child, extra=extra)

    return NodeHandleResult()
