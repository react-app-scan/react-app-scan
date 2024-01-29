from src.core.jsx_constant import JSX_WHITE_LIST_PACKAGE, JSX_WHITE_LITE_IMPORT_SPECIFIER
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer, wildcard, NodeHandleResult, ExtraInfo
from src.core.esprima import esprima_search, esprima_parse
from src.core.checker import traceback, vul_checking
from src.core.garbage_collection import cleanup_scope
from src.core.options import options
from src.plugins.handler import Handler
from src.plugins.internal.modeled_js_builtins import setup_react_dom, setup_dom_purify, setup_markdown_it, setup_sanitize_html
from . import file


class HandleImportDeclaration(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        """
        the pre processing function
        """
        r = ast_import_declaration(self.G, self.node_id, self.extra)
        return r


def get_specifier_name(G: Graph, specifier_ast_node):
    identifier_children = G.get_ordered_ast_child_nodes(specifier_ast_node)
    imported_identifier = identifier_children[0]
    local_identifier = identifier_children[1]
    return G.get_node_attr(imported_identifier), G.get_node_attr(local_identifier)


def ast_import_declaration(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    source = G.get_import_declaration_source(ast_node)
    source_file_path = G.get_node_attr(ast_node).get('name')

    module_info = G.module_registry.get(source_file_path)
    module_state = module_info['state'] if (module_info and ('state' in module_info)) else None
    loggers.main_logger.info(f'module_state: {module_state}')
    create_stub = False
    if module_state == 'Loading':
        # create stub
        # 1. get the specifiers of source_file_path
        specifier_list = G.get_import_declaration_specifier_ast_list(ast_node)
        loggers.main_logger.info(f'creating stubs for {source_file_path} {specifier_list}')
        create_stub = True
        # 2. create a stub for each of the specifiers
        # 3. return stubs

    returned_objs = set()
    jsx_nodes = set()

    is_purify_lib = False
    if source['code'] == 'react':
        return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))

    if source['code'] == 'react-dom':
        setup_react_dom(G=G, scope=G.cur_scope)

    if source['code'] in JSX_WHITE_LIST_PACKAGE:
        return NodeHandleResult()

    source_module_scope_list = get_file_scope_by_module_path(G, source_file_path)
    loggers.main_logger.info(f'source_module_scope for {source_file_path}: {source_module_scope_list}')

    specifier_list = G.get_import_declaration_specifier_ast_list(ast_node)
    if not source_file_path:
        # if the file path is not found, add a wildcard object
        for specifier_ast in specifier_list:
            imported_identifier, local_identifier = get_specifier_name(G, specifier_ast)
            if source['code'] == 'dompurify':
                specifier_obj_list = setup_dom_purify(G, scope=G.cur_scope).obj_nodes
            elif source['code'] == 'markdown-it':
                specifier_obj_list = setup_markdown_it(G, scope=G.cur_scope).obj_nodes
            elif source['code'] == 'sanitize-html':
                specifier_obj_list = setup_sanitize_html(G, scope=G.cur_scope).obj_nodes
            else:
                specifier_obj_list = [G.add_obj_node(ast_node=ast_node, js_type='object', value=wildcard)]
            specifier_name_node = G.add_name_node(local_identifier['name'], scope=G.cur_scope)
            for specifier_obj in specifier_obj_list:
                specifier_obj_attr = G.get_node_attr(specifier_obj)
                specifier_obj_type = specifier_obj_attr.get('type')
                G.add_obj_to_name_node(name_node=specifier_name_node, ast_node=ast_node, js_type=specifier_obj_type, tobe_added_obj=specifier_obj)
    else:
        # If the file path is found, get the module's exports
        if not create_stub:
            module_exports_objs = ES6_get_module_exports(G, source_file_path)
        else:
            module_exports_objs = []
            for specifier_ast in specifier_list:
                stub_obj = G.add_obj_node(ast_node=ast_node, js_type='object')
                loggers.main_logger.info(f'created stub {stub_obj} for AST {specifier_ast}')
                G.set_node_attr(stub_obj, ('es6_stub', True))
                G.set_node_attr(stub_obj, ('es6_stub_file_path', source_file_path))
                G.set_node_attr(stub_obj, ('ES6_export_default', True))
                module_exports_objs.append(stub_obj)

        if not module_exports_objs:
            # syntax error in application code could casue no exports. e.g., invaid syntax caused ast parsing failed. or use module.exports in es6 modules.
            loggers.main_logger.warn(f"Cannot import from '{source_file_path}' as it has no exports. AST node: {ast_node}")
            for specifier_ast in specifier_list:
                imported_identifier, local_identifier = get_specifier_name(G, specifier_ast)
                specifier_obj = G.add_obj_node(ast_node=ast_node, js_type='object', value=wildcard)
                specifier_name_node = G.add_name_node(local_identifier['name'], scope=G.cur_scope)
                G.add_obj_to_name_node(name_node=specifier_name_node, ast_node=ast_node, js_type='object', tobe_added_obj=specifier_obj)
                returned_objs.update([specifier_obj])
            return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))

        # then add specifiers to current file scope
        for specifier_ast in specifier_list:
            specifier = G.get_node_attr(specifier_ast)
            specifier_type = specifier['type']
            imported_identifier, local_identifier = get_specifier_name(G, specifier_ast)
            imported_specifier_name = imported_identifier['name']
            local_specifier_name = local_identifier['name']
            if specifier_type == 'AST_ImportDefaultSpecifier':
                scope = G.find_ancestor_scope()
                cur_name_node = G.get_name_node(var_name=local_identifier, scope=scope)
                if cur_name_node is not None:
                    continue
                added_name_node = G.add_name_node(name=local_specifier_name, scope=scope)
                module_export_default_objs = []
                for obj in module_exports_objs:
                    if create_stub:
                        G.set_node_attr(obj, ('ES6_stub_specifier_name', 'ES6_stub_export_default'))
                        continue
                    node_attr = G.get_node_attr(obj)
                    if 'ES6_export_default' in node_attr and node_attr['ES6_export_default'] == True:
                        added_obj = G.add_obj_to_name_node(name_node=added_name_node, ast_node=ast_node, tobe_added_obj=obj)
                        module_export_default_objs.append(obj)
                if not module_export_default_objs:
                    # Handle the scenario where 'export default' fails and the default object is missing.
                    # This could happen due to errors during the export process or if the export is not explicitly defined.
                    # Log a warning and then create a 'wildcard' object to represent the unspecified default export.
                    loggers.main_logger.warn(f'Could not find export default obj, {imported_specifier_name} {module_exports_objs} {source_file_path} create_stub: {create_stub}')
                    added_obj_node = G.add_obj_node(ast_node=ast_node, js_type='object', value=wildcard)
                    added_obj = G.add_obj_to_name_node(name_node=added_name_node, ast_node=ast_node, tobe_added_obj=added_obj_node)
            elif specifier_type == 'AST_ImportSpecifier':
                if imported_specifier_name in JSX_WHITE_LITE_IMPORT_SPECIFIER:
                    continue
                same_name_exported_obj_list = set()
                scope = G.find_ancestor_scope()
                cur_name_node = G.get_name_node(var_name=local_identifier, scope=scope)
                if cur_name_node is not None:
                    continue
                added_name_node = G.add_name_node(name=local_specifier_name, scope=scope)
                for exported_obj in module_exports_objs:
                    if create_stub:
                        G.set_node_attr(exported_obj, ('ES6_stub_specifier_name', imported_specifier_name))
                        continue
                    name_nodes = G.get_name_nodes_to_obj_by_scope(exported_obj, source_module_scope_list)
                    for name_node in name_nodes:
                        name_node_attr = G.get_node_attr(name_node)
                        name = name_node_attr['name']
                        if imported_specifier_name == name:
                            same_name_exported_obj_list.add(exported_obj)
                            break
                for same_name_exported_obj in same_name_exported_obj_list:
                    loggers.main_logger.info(f'imported {same_name_exported_obj} to name node {added_name_node}, specifier: {local_specifier_name}')
                    added_obj = G.add_obj_to_name_node(name_node=added_name_node, ast_node=ast_node, tobe_added_obj=same_name_exported_obj)
                if not same_name_exported_obj_list:
                    loggers.main_logger.warn(f'does not have same name {specifier["code"]} create_stub: {create_stub} {source_file_path}')

        if module_exports_objs:
            returned_objs.update(module_exports_objs)
        else:
            # raise ValueError(f"Couldn't find imported objs, source_file_path: {source_file_path}")
            pass
    return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))


def ES6_get_module_exports(G: Graph, file_path: str):
    toplevel_nodes = G.get_nodes_by_type_and_flag('AST_TOPLEVEL', 'TOPLEVEL_FILE')
    found = False
    for node in toplevel_nodes:
        if G.get_node_attr(node).get('name') == file_path:
            found = True
            # if a file has been required, skip the run and return
            # the saved module.exports
            saved_module_exports = G.get_node_attr(node).get('module_exports')
            if saved_module_exports != None:
                module_exports_objs = saved_module_exports
                break
            else:
                module_exports_objs = file.ES6_run_toplevel_file(G, node)
                G.set_node_attr(node, ('module_exports', module_exports_objs))
                break
    if found:
        return module_exports_objs
    else:
        return []


def get_file_scope_by_module_path(G: Graph, file_path: str):
    toplevel_nodes = G.get_nodes_by_type_and_flag('AST_TOPLEVEL', 'TOPLEVEL_FILE')
    for node in toplevel_nodes:
        if G.get_node_attr(node).get('name') == file_path:
            scope_nodes = G.get_scope_by_file_ast(node)
            return scope_nodes
    return []
