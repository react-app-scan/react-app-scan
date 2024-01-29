
from src.core.jsx_constant import JSX_DOM_events
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
import traceback as tb
from collections import defaultdict
from src.core.options import options
from src.core.utils import get_random_hex, wildcard, undefined, BranchTag


class HandleObjectPatternElem(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_object_pattern_elem(self.G, self.node_id, self.extra)
        return r


def ast_object_pattern_elem(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    value_node, key_node = G.get_ordered_ast_child_nodes(ast_node)
    value_node_attr = G.get_node_attr(value_node)
    key = G.get_name_from_child(key_node)
    if key is not None:
        key = key.strip("'\"")
    else:
        key = G.get_node_attr(ast_node).get('childnum:int')
    if key is None:
        raise ValueError('Object Pattern Key is None')
    if not extra.parent_obj:
        raise ValueError('Object Pattern could not find parent_obj')

    handled_value = internal_manager.dispatch_node(value_node, extra)
    value_objs = to_obj_nodes(G, handled_value, ast_node)

    parent_obj_attr = G.get_node_attr(extra.parent_obj)
    obj_nodes = G.get_prop_obj_nodes(parent_obj=extra.parent_obj, prop_name=key, branches=extra.branches)
    element_type = value_node_attr['type']
    if element_type == 'AST_VAR':
        # function ({foo, bar}, ) {...}
        for obj in obj_nodes:
            G.add_obj_to_scope(name=key, ast_node=ast_node, scope=extra.scope, tobe_added_obj=obj)
            loggers.main_logger.info(f'handling obj pattern param: {key} obj {obj} under scope {extra.scope}')
        return NodeHandleResult(obj_nodes=obj_nodes, name=key, callback=get_df_callback(G))
    elif element_type == 'AST_ARRAY':
        prop_name_nodes = G.get_prop_name_nodes(value_objs[0], exclude_proto=True)
        name_nodes = []
        for name_node in prop_name_nodes:
            name_node_attr = G.get_node_attr(name_node)
            name = name_node_attr['name']
            if name == 'length':
                continue
            for obj_node in obj_nodes:
                if G.get_node_attr(obj_node).get('code') == wildcard:
                    loggers.main_logger.info(f'obj_prop_nodes is wildcard: {obj_node} {name}')
                    name_nodes.append(name_node)
                    G.add_obj_to_scope(name=name, ast_node=ast_node, scope=extra.scope, tobe_added_obj=obj_node)
                else:
                    loggers.main_logger.info('handling non-wildcard object pattern')

        return NodeHandleResult(obj_nodes=obj_nodes, name=key, callback=get_df_callback(G), name_nodes=name_nodes)
    else:
        return NodeHandleResult(obj_nodes=[], name=key)
