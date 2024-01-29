from src.core.logger import *
from src.core.utils import NodeHandleResult, ExtraInfo
from src.core.options import options
import time
# function is higher than block
# a little bit risky to use handle prop
# should be fine
from . import vars
from . import property
from src.core.helpers import to_values
from src.plugins.handler import Handler
from itertools import chain
from . import file
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
import traceback as tb
from collections import defaultdict
from src.core.options import options


class HandleJSXText(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_text(self.G, self.node_id, self.extra)
        return NodeHandleResult(obj_nodes=r.obj_nodes, used_objs=r.used_objs,
                                values=r.values, value_sources=r.value_sources,
                                ast_node=self.node_id, callback=get_df_callback(self.G), jsx_nodes=r.jsx_nodes)


def ast_jsx_text(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    node_attr = G.get_node_attr(ast_node)
    jsx_text = node_attr['code']

    loggers.main_logger.log(ATTENTION, 'JSX Text {}'.format(jsx_text))

    jsx_text_node = G.add_dom_node(ast_node, 'text')

    if extra.parent_component:
        G.add_jsx_parent_of_edge(extra.parent_component, jsx_text_node)

    return NodeHandleResult()
