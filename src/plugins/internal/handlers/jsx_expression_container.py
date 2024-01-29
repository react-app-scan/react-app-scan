from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
from src.core.esprima import esprima_search, esprima_parse
from src.core.checker import traceback, vul_checking
from src.core.garbage_collection import cleanup_scope
from src.core.helpers import to_values
from src.plugins.handler import Handler
from itertools import chain
from . import file
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
import traceback as tb
from collections import defaultdict
from src.core.options import options


class HandleJSXExpressionContainer(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_expression_container(self.G, self.node_id, self.extra)
        return r


def ast_jsx_expression_container(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    expression = G.get_ordered_ast_child_nodes(ast_node)[0]
    loggers.main_logger.log(ATTENTION, 'JSX Expression Container {}, expression {}'.format(ast_node, expression))

    internal_manager.dispatch_node(expression, extra)

    return NodeHandleResult(callback=get_df_callback(G))
