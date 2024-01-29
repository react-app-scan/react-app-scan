from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler
from ..utils import get_df_callback
from src.plugins.internal.handlers.vars import handle_var
from src.plugins.internal.handlers.func_decl import decl_function
from src.core.helpers import to_values, to_obj_nodes, add_contributes_to, val_to_float


class HandleExportDefaultDeclaration(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_export_default(self.G, self.node_id, self.extra)
        return NodeHandleResult(obj_nodes=r.obj_nodes, used_objs=r.used_objs,
                                values=r.values, value_sources=r.value_sources,
                                ast_node=self.node_id, callback=get_df_callback(self.G), jsx_nodes=r.jsx_nodes)


def ast_export_default(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    cur_file_path = G.get_cur_file_path()
    stub_objs = G.get_node_by_attr('es6_stub', True)
    cur_file_stub_objs = []
    for stub_obj in stub_objs:
        stub_obj_attr = G.get_node_attr(stub_obj)
        if cur_file_path == stub_obj_attr.get('es6_stub_file_path'):
            cur_file_stub_objs.append(stub_obj)
    loggers.main_logger.info(f'cur_file_stub_objs: {cur_file_stub_objs}')

    # here we assume there's one and only one export default specifier.
    assert len(G.get_ordered_ast_child_nodes(ast_node)) == 1
    exported_ast_node = G.get_ordered_ast_child_nodes(ast_node)[0]
    exported_ast_node_attr = G.get_node_attr(exported_ast_node)

    exported_ast_node_type = exported_ast_node_attr['type']

    r = internal_manager.dispatch_node(exported_ast_node, extra=ExtraInfo(extra, side='right'))

    exported_obj_nodes = to_obj_nodes(G, r, ast_node=ast_node)

    # # AST_CLASS is not supported now
    # if len(exported_obj_nodes) == 0 and exported_ast_node_type == 'AST_CLASS':
    #     return r

    for exported_obj in exported_obj_nodes:
        G.set_node_attr(exported_obj, ('ES6_export_default', True))

        add_exported_obj_to_file_scope(G=G, name='ES6_export_default', exported_obj=exported_obj)

        if cur_file_stub_objs:
            for stub_obj in stub_objs:
                stub_obj_attr = G.get_node_attr(stub_obj)
                loggers.main_logger.info(f'stub ob here {stub_obj} {stub_obj_attr}')
                if 'ES6_stub_specifier_name' in stub_obj_attr and stub_obj_attr['ES6_stub_specifier_name'] == 'ES6_stub_export_default':
                    name_nodes = G.get_name_nodes_to_obj(stub_obj)
                    for name_node in name_nodes:
                        G.add_obj_to_name_node(name_node=name_node, tobe_added_obj=exported_obj)
                        G.remove_all_edges_between(stub_obj, name_node)
                        G.set_node_attr(stub_obj, ('es6_stub', False))
                if 'ES6_stub_specifier_name' not in stub_obj_attr:
                    loggers.main_logger.warn(f'can not find the specifier name of stub {stub_obj}, AST: {ast_node}')

    return r


def add_exported_obj_to_file_scope(G: Graph, name: str, exported_obj):
    file_scope = G.find_ancestor_scope()
    file_scope_attr = G.get_node_attr(file_scope)

    if file_scope_attr['type'] != 'FILE_SCOPE':
        raise ValueError(f"Couldn't find export default declaration's file_scope, {file_scope}")

    file_scope_ast = G.get_ast_by_scope(file_scope)

    added_export_default_node = G.add_obj_to_scope(name=name, ast_node=file_scope_ast, scope=file_scope, tobe_added_obj=exported_obj)

    loggers.main_logger.info(f'Added exported_obj {exported_obj} to file_scope {file_scope}, name: {name}, added_node = {added_export_default_node}')
