from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo, BranchTagContainer
from src.core.logger import *
# file level handling is higher than function level
# we can safely import function level functions
from .functions import simurun_function, ES6_simurun_function
from ..utils import decl_function
from src.plugins.handler import Handler
from src.plugins.internal.handlers.class_ import handle_class


class HandleFile(Handler):

    def process(self):
        """
        handle the file node type
        Args:
            G (Graph): the graph
            node_id (str): the node id
        Returns:
            NodeHandleResult: the handle result
        """
        for child in self.G.get_child_nodes(self.node_id):
            self.internal_manager.dispatch_node(child, self.extra)

class HandleToplevel(Handler):

    def process(self):
        """
        handle the toplevel node type
        Args:
            G (Graph): the graph
            node_id (str): the node id
        Returns:
            NodeHandleResult: the handle result
        """
        flags = self.G.get_node_attr(self.node_id).get('flags:string[]')
        if flags == 'TOPLEVEL_FILE':
            if options.nodejs:
                module_exports_objs = run_toplevel_file(self.G, self.node_id)
            else:
                module_exports_objs = ES6_run_toplevel_file(self.G, self.node_id)
            return NodeHandleResult(obj_nodes=module_exports_objs)
        elif flags == 'TOPLEVEL_CLASS':
            handle_class(self.G, self.node_id, self.extra)

def run_toplevel_file(G: Graph, node_id):
    """
    run a top level file 
    return a obj and scope
    """
    # switch current file path
    file_path = None
    if 'name' in G.get_node_attr(node_id):
        file_path = G.get_node_attr(node_id)['name']
    else:
        loggers.main_logger.error("[ERROR] " + node_id + "no file name")

    # loop call
    if file_path in G.file_stack:
        return []
    G.file_stack.append(file_path)
    if options.max_file_stack is not None:
        if len(G.file_stack) > options.max_file_stack + 1:
            return []
    previous_file_path = G.cur_file_path
    G.cur_file_path = file_path
    if G.entry_file_path is None:
        G.entry_file_path = file_path
    loggers.main_logger.info(sty.fg(173) + sty.ef.inverse + 'FILE {} BEGINS'.format(file_path) + sty.rs.all)

    # add function object and scope
    func_decl_obj = decl_function(G, node_id, func_name=file_path,
                                  obj_parent_scope=G.BASE_SCOPE, scope_parent_scope=G.BASE_SCOPE)
    func_scope = G.add_scope(scope_type='FILE_SCOPE', decl_ast=node_id,
                             scope_name=G.scope_counter.gets(f'File{node_id}'),
                             decl_obj=func_decl_obj, func_name=file_path, parent_scope=G.BASE_SCOPE)

    backup_scope = G.cur_scope
    G.cur_scope = func_scope
    backup_stmt = G.cur_stmt

    # add module object to the current file's scope
    added_module_obj = G.add_obj_to_scope("module", node_id)
    # add module.exports
    added_module_exports = G.add_obj_as_prop("exports", node_id,
                                             parent_obj=added_module_obj)
    # add module.exports as exports
    G.add_obj_to_scope(name="exports", tobe_added_obj=added_module_exports)
    # "this" is set to module.exports by default
    # backup_objs = G.cur_objs
    # G.cur_objs = added_module_exports
    # TODO: this is risky
    G.add_obj_to_scope(name="this", tobe_added_obj=added_module_exports)

    # simurun the file
    simurun_function(G, node_id, block_scope=True)

    # get current module.exports
    # because module.exports may be assigned to another object
    # TODO: test if module is assignable
    module_obj = G.get_objs_by_name('module')[0]
    module_exports_objs = G.get_prop_obj_nodes(parent_obj=module_obj,
                                               prop_name='exports')

    # final_exported_objs = []
    """
    for obj in module_exports_objs:
        for o in G.get_prop_obj_nodes(obj):
            print('exported', G.get_node_attr(o))
    """
    # switch back scope, object, path and statement AST node id
    G.cur_scope = backup_scope
    # G.cur_objs = backup_objs
    G.cur_file_path = previous_file_path
    G.cur_stmt = backup_stmt

    G.file_stack.pop(-1)
    loggers.main_logger.info("{} exported".format(file_path))
    for nn in G.get_prop_name_nodes(module_exports_objs[0]):
        loggers.main_logger.info("\t{}".format(G.get_node_attr(nn)))

    return module_exports_objs


def ES6_run_toplevel_file(G: Graph, node_id):
    """
    run a top level file 
    return a obj and scope
    @params node_id: TOPLEVEL_FILE node ID
    """
    # switch current file path
    file_path = None
    if 'name' in G.get_node_attr(node_id):
        file_path = G.get_node_attr(node_id)['name']
    else:
        loggers.main_logger.error("[ERROR] " + node_id + "no file name")

    loggers.main_logger.info(f'G.file_stack: {G.file_stack}')
    # loop call
    if file_path in G.file_stack:
        loggers.main_logger.info(f'return here: {G.file_stack} {G.module_registry}')
        # return []
    G.file_stack.append(file_path)
    if options.max_file_stack is not None:
        if len(G.file_stack) > options.max_file_stack + 1:
            return []
      
    G.module_registry[file_path] = {
        "state": 'Loading'
    }
    previous_file_path = G.cur_file_path
    G.cur_file_path = file_path

    if G.entry_file_path is None:
        G.entry_file_path = file_path

    loggers.main_logger.info(sty.fg(173) + sty.ef.inverse + 'RUNNING TOP_LEVEL_FILE BEGINS: {}'.format(file_path) + sty.rs.all)

    # add function object and scope
    func_decl_obj = decl_function(G, node_id=node_id, func_name=file_path, obj_parent_scope=G.BASE_SCOPE, scope_parent_scope=G.BASE_SCOPE)
    func_scope = G.add_scope(scope_type='FILE_SCOPE', decl_ast=node_id, scope_name=G.scope_counter.gets(
        f'File{node_id}'), decl_obj=func_decl_obj, func_name=file_path, parent_scope=G.BASE_SCOPE)

    backup_scope = G.cur_scope
    G.cur_scope = func_scope
    backup_stmt = G.cur_stmt

    loggers.main_logger.info(f'ES6_run_toplevel_file, file_path {file_path}, switch to scope {G.cur_scope}')

    # simurun the file
    loggers.main_logger.info(f'ES6 simu run function  file_path {file_path} {G.cur_scope}')

    returned_objs, used_objs = ES6_simurun_function(G, func_ast=node_id, block_scope=False)

    loggers.main_logger.info(f'ES6 simu run function  file_path {returned_objs} {used_objs}')

    # get current module.exports
    # because module.exports may be assigned to another object
    # TODO: test if module is assignable

    # TODO: there might be more than one exported objs. There's will only be one if it's export default
    # FIXME: Ensure that the exported objects are correctly bound to either the function scope or the file scope.

    module_export_default_objs = G.get_objs_by_name('ES6_export_default', scope=func_scope)
    module_export_named_objs = G.get_objs_by_name('ES6_export_named', scope=func_scope)

    module_exports_objs = module_export_default_objs + module_export_named_objs
    loggers.main_logger.info(f'Get ES6 exports objs: file_path {file_path} {module_exports_objs}')

    # if module_export_default_objs:
    #     module_exports_objs.extend(module_export_default_objs)

    # module_obj = G.get_objs_by_name('module')[0]

    # module_exports_objs = G.get_prop_obj_nodes(parent_obj=module_obj, prop_name='exports')

    # switch back scope, object, path and statement AST node id
    G.cur_scope = backup_scope
    # G.cur_objs = backup_objs
    G.cur_file_path = previous_file_path
    G.cur_stmt = backup_stmt

    G.file_stack.pop(-1)
    G.module_registry[file_path] = {
        "state": 'Loaded'
    }
    # loggers.main_logger.info("{} exported: ".format(file_path))

    # if module_exports_objs:
    #     for nn in G.get_prop_name_nodes(module_exports_objs[0]):
    #         loggers.main_logger.info("\t{}".format(G.get_node_attr(nn)))

    return list(set(module_exports_objs))
