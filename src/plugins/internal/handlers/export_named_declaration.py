from src.plugins.internal.handlers.export_default import add_exported_obj_to_file_scope
from src.plugins.internal.handlers.import_declaration import ES6_get_module_exports
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler
from ..utils import get_df_callback, to_obj_nodes, add_contributes_to, merge
from src.plugins.internal.handlers.vars import handle_var


class HandleExportNamedDeclaration(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        """
        the pre processing function
        """
        r = ast_export_named_declaration(self.G, self.node_id, self.extra)
        return NodeHandleResult(obj_nodes=r.obj_nodes, used_objs=r.used_objs,
                                values=r.values, value_sources=r.value_sources,
                                ast_node=self.node_id, callback=get_df_callback(self.G), jsx_nodes=r.jsx_nodes)


def ast_export_named_declaration(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    returned_objs = set()
    jsx_nodes = set()

    cur_file_path = G.get_cur_file_path()
    stub_objs = G.get_node_by_attr('es6_stub', True)
    cur_file_stub_objs = []
    for stub_obj in stub_objs:
        stub_obj_attr = G.get_node_attr(stub_obj)
        if cur_file_path == stub_obj_attr.get('es6_stub_file_path'):
            cur_file_stub_objs.append(stub_obj)

    source_file_path = G.get_node_attr(ast_node).get('name')
    if source_file_path:
        handle_export_from_source(G=G, source_file_path=source_file_path, ast_node=ast_node, cur_file_path=cur_file_path, extra=extra, cur_file_stub_objs=cur_file_stub_objs)
    else:
        exported_declarations = G.get_ordered_ast_child_nodes(ast_node)
        if len(exported_declarations) == 0:
            # This is possible, for example, export {}, which exports nothing
            return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))
        if len(exported_declarations) == 1:
            ast_child = exported_declarations[0]
            ast_child_attr = G.get_node_attr(ast_child)
            ast_child_type = ast_child_attr['type']
            if ast_child_type == 'AST_ASSIGN' or ast_child_type == 'AST_FUNC_DECL' or ast_child_type == 'AST_CLASS':
                handle_export_declaration(G=G, declaration_ast_node=ast_child, extra=extra, stub_objs=cur_file_stub_objs)
            elif ast_child_type == 'AST_ExportNamedDeclaration_Specifier':
                handle_export_specifier(G=G, specifier_node=ast_child, extra=extra, stub_objs=cur_file_stub_objs)
            else:
                raise ValueError(f'Unsupported export named declaration type {ast_child_type}')
            loggers.main_logger.info(f'export named ast_child {ast_child} {ast_child_attr}')
        else:
            for decl in exported_declarations:
                handle_export_specifier(G=G, specifier_node=decl, extra=extra, stub_objs=cur_file_stub_objs)

    return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))


def handle_export_from_source(G: Graph, source_file_path: str, ast_node: str, cur_file_path, extra, cur_file_stub_objs):
    """export { Faq } from "./src/components/Faq"
    1. get all the exports in source_file_path
    2. handle exports objs: add them to current scopes
    """
    source_node = None
    toplevel_nodes = G.get_nodes_by_type_and_flag('AST_TOPLEVEL', 'TOPLEVEL_FILE')
    for node in toplevel_nodes:
        if G.get_node_attr(node).get('name') == source_file_path:
            source_node = node

    if not source_node:
        loggers.main_logger.warn(f"[Export Named Declaration] Couldn't find the source for {source_file_path}, AST_Node: {ast_node}")
        return []
        # raise ValueError(f"[Export Named Declaration] Couldn't find the source for {file_path}, AST_Node: {ast_node}")

    module_exports_objs = ES6_get_module_exports(G, source_file_path)

    exported_declarations = G.get_ordered_ast_child_nodes(ast_node)
    for decl in exported_declarations:
        local, exported = G.get_ordered_ast_child_nodes(decl)

        local_attr = G.get_node_attr(local)
        if local_attr['type'] != 'AST_VAR':
            raise ValueError(f'Unsupported local type for export named declaration, {local_attr["type"]}')

        local_r = handle_var(G, ast_node=local, side='right', extra=ExtraInfo(original=extra, side='right', scope=G.find_ancestor_scope()))
        exported_r = handle_var(G, ast_node=exported, side='right', extra=ExtraInfo(original=extra, side='right', scope=G.find_ancestor_scope()))

        local_specifier_name = local_r.name
        exported_specifier_name = exported_r.name

        if local_specifier_name == 'default':
            # export { default as Foo } from "./bar.js"
            for export_obj in module_exports_objs:
                export_obj_attr = G.get_node_attr(export_obj)
                if 'ES6_export_default' in export_obj_attr:
                    handle_exported_objs(G, [export_obj], exported_specifier_name, stub_objs=cur_file_stub_objs)
        else:
            # export { Foo } from "./bar.js"
            for export_obj in module_exports_objs:
                export_obj_attr = G.get_node_attr(export_obj)
                if 'ES6_export_default' not in export_obj_attr:
                    handle_exported_objs(G, [export_obj], exported_specifier_name, stub_objs=cur_file_stub_objs)

    return module_exports_objs


def handle_export_declaration(G: Graph, declaration_ast_node, extra, stub_objs=None):
    """e.g., export const foo = 1;

    e.g., export function foo() {}
    """
    from src.plugins.manager_instance import internal_manager
    r = internal_manager.dispatch_node(declaration_ast_node, extra)

    exported_obj_nodes = r.obj_nodes
    specifier_name = r.name

    # AST_FUNC_DECL only returns an object without name
    if not specifier_name and r.obj_nodes:
        if len(r.obj_nodes) == 1:
            obj_node = r.obj_nodes[0]
            obj_node_attr = G.get_node_attr(obj_node)
            if 'name' in obj_node_attr:
                specifier_name = obj_node_attr['name']

    handle_exported_objs(G, exported_obj_nodes=exported_obj_nodes, specifier_name=specifier_name, stub_objs=stub_objs)

    return r


def handle_export_specifier(G: Graph, specifier_node, extra, stub_objs=None):
    """e.g., export { RichText }
    """

    local, exported = G.get_ordered_ast_child_nodes(specifier_node)

    local_attr = G.get_node_attr(local)
    if local_attr['type'] != 'AST_VAR':
        raise ValueError(f'Unsupported local type for export named declaration, {local_attr["type"]}')

    r = handle_var(G, ast_node=local, side='right', extra=ExtraInfo(original=extra, side='right', scope=G.find_ancestor_scope()))

    exported_obj_nodes = r.obj_nodes

    specifier_name = r.name

    handle_exported_objs(G, exported_obj_nodes=exported_obj_nodes, specifier_name=specifier_name, stub_objs=stub_objs)
    return r


def handle_exported_objs(G: Graph, exported_obj_nodes, specifier_name, stub_objs=[]):
    for exported_obj in exported_obj_nodes:
        add_exported_obj_to_file_scope(G=G, name='ES6_export_named', exported_obj=exported_obj)
        add_exported_obj_to_file_scope(G=G, name=specifier_name, exported_obj=exported_obj)

    # if there's stub objs, replace the stub with real obj
    for stub_obj in stub_objs:
        stub_obj_attr = G.get_node_attr(stub_obj)
        loggers.main_logger.info(f'stub {stub_obj}')
        if ('ES6_stub_specifier_name' in stub_obj_attr) and stub_obj_attr['ES6_stub_specifier_name'] == specifier_name:
            loggers.main_logger.info(f'found stub for {specifier_name}')
            name_nodes = G.get_name_nodes_to_obj(stub_obj)
            for name_node in name_nodes:
                G.add_obj_to_name_node(name_node=name_node, tobe_added_obj=exported_obj)
                G.remove_all_edges_between(stub_obj, name_node)
                G.set_node_attr(stub_obj, ('es6_stub', False))
