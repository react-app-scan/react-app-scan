from src.plugins.handler import Handler
from src.core.utils import BranchTagContainer, ExtraInfo, NodeHandleResult
from src.core.graph import Graph
from src.core.logger import loggers
from . import func_decl
from src.plugins.internal.handlers.func_decl import decl_function


class HandleClass(Handler):
    """
    hander for class
    """

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = handle_class(self.G, self.node_id, self.extra)
        return r


class HandleMethod(Handler):
    """
    hander for class method
    """

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = handle_method(self.G, self.node_id, self.extra)
        return r


def handle_class(G: Graph, ast_node, extra):
    loggers.main_logger.info(f'handle class {ast_node}')
    children = G.get_ordered_ast_child_nodes(ast_node)
    name = G.get_node_attr(children[0]).get('code')
    class_obj = G.add_obj_node(ast_node=None, js_type='function')
    G.set_node_attr(class_obj, ('name', name))
    G.set_node_attr(class_obj, ('value', f'[class {name}]'))
    G.set_node_attr(class_obj, ('class_obj', True))
    # print(ast_node, G.get_node_attr(ast_node), children)
    toplevel = children[4]
    body = G.get_child_nodes(toplevel, edge_type='PARENT_OF', child_type='AST_STMT_LIST')[0]
    prev_dont_quit = G.dont_quit
    G.dont_quit = 'class'
    simurun_class_body(G, body, ExtraInfo(extra, class_obj=class_obj))
    G.dont_quit = prev_dont_quit
    if G.get_obj_def_ast_node(class_obj) is None:
        ast = G.add_blank_func(name)
        G.add_edge(class_obj, ast, {'type:TYPE': 'OBJ_TO_AST'})
    if G.find_nearest_upper_CPG_node(ast_node) == ast_node:
        G.add_obj_to_scope(name, tobe_added_obj=class_obj)
    return NodeHandleResult(obj_nodes=[class_obj])


def handle_method(G: Graph, ast_node, extra):
    name = G.get_name_from_child(ast_node)
    if extra.class_obj is None:
        loggers.main_logger.info(f'class obj is None, ast node: {ast_node}, name: {name} {extra}')
        return
    if name == 'constructor':
        G.add_edge(extra.class_obj, ast_node, {'type:TYPE': 'OBJ_TO_AST'})
    else:
        method_obj = decl_function(G, ast_node, add_to_scope=False)
        prototypes = G.get_prop_obj_nodes(extra.class_obj, 'prototype', branches=extra.branches)
        for p in prototypes:
            G.add_obj_as_prop(name, parent_obj=p, tobe_added_obj=method_obj)


def simurun_class_body(G, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    """
    Simurun the body of a class
    """
    if extra is None or extra.branches is None:
        branches = BranchTagContainer()
    else:
        branches = extra.branches

    loggers.main_logger.info('BLOCK {} STARTS, SCOPE {}'.format(ast_node, G.cur_scope))
    stmts = G.get_ordered_ast_child_nodes(ast_node)
    # control flows
    for last_stmt in G.last_stmts:
        G.add_edge_if_not_exist(last_stmt, ast_node, {'type:TYPE': 'FLOWS_TO'})
    G.last_stmts = [ast_node]
    # simulate statements
    for stmt in stmts:
        # build control flows from the previous statement to the current one
        for last_stmt in G.last_stmts:
            G.add_edge_if_not_exist(last_stmt, stmt, {'type:TYPE': 'FLOWS_TO'})
        G.last_stmts = [stmt]
        G.cur_stmt = stmt
        internal_manager.dispatch_node(stmt, ExtraInfo(extra, branches=branches))

        if G.finished or G.time_limit_reached:
            break

        if G.get_node_attr(stmt).get('type') == 'AST_RETURN':
            G.last_stmts = []
