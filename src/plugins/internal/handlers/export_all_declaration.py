from src.plugins.internal.handlers.import_declaration import ES6_get_module_exports
from src.plugins.internal.handlers.export_default import add_exported_obj_to_file_scope
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import BranchTagContainer
from src.core.utils import NodeHandleResult, ExtraInfo
from src.core.esprima import esprima_search, esprima_parse
from src.core.checker import traceback, vul_checking
from src.core.garbage_collection import cleanup_scope
from src.core.options import options
from . import vars
from . import property
from src.core.utils import get_random_hex, wildcard, undefined, BranchTag
from src.core.helpers import to_values
from src.plugins.handler import Handler
from itertools import chain
from . import file
from ..utils import get_df_callback


class HandleExportAllDeclaration(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        """
        the pre processing function
        """
        r = ast_export_all_declaration(self.G, self.node_id, self.extra)
        return NodeHandleResult(obj_nodes=r.obj_nodes, used_objs=r.used_objs,
                                values=r.values, value_sources=r.value_sources,
                                ast_node=self.node_id, callback=get_df_callback(self.G), jsx_nodes=r.jsx_nodes)


def ast_export_all_declaration(G: Graph, ast_node, extra):
    """
    e.g., export * from './field';
    """
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    returned_objs = set()
    jsx_nodes = set()

    node_attr = G.get_node_attr(ast_node)
    source_file_path = node_attr.get('name')

    module_exports_objs = ES6_get_module_exports(G, source_file_path)

    loggers.main_logger.info(f'export all module_exports_objs {source_file_path} {module_exports_objs}')

    for exported_obj in module_exports_objs:
        add_exported_obj_to_file_scope(G=G, name='ES6_export_named', exported_obj=exported_obj)

    if module_exports_objs:
        returned_objs.update(module_exports_objs)
    else:
        # It is possible. For instance, export {}
        loggers.main_logger.warn(f'export all returns nothing, ast_node {ast_node} {node_attr} file_path: {source_file_path} module_exports_objs: {module_exports_objs}')

    returned_objs = list(returned_objs)

    return NodeHandleResult(obj_nodes=list(returned_objs), jsx_nodes=list(jsx_nodes))
