from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler


class HandleJSXFragment(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_element(self.G, self.node_id, self.extra)
        return r


def ast_jsx_element(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    jsx_element_children = G.get_ordered_ast_child_nodes(ast_node)
    loggers.main_logger.log(ATTENTION, 'Handling JSX Fragment {}, children {}'.format(ast_node, jsx_element_children))

    component_node = G.add_dom_node(ast_node, '</>')

    if extra.parent_component:
        G.add_jsx_parent_of_edge(extra.parent_component, component_node)

    for ast_child in jsx_element_children:
        G.cur_stmt = ast_child
        internal_manager.dispatch_node(ast_child, ExtraInfo(extra, parent_component=component_node))

    return NodeHandleResult(jsx_nodes=[component_node])
