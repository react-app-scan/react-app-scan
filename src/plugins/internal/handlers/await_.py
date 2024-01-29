from src.core.graph import Graph
from src.plugins.handler import Handler
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.internal.utils import get_df_callback, to_obj_nodes
from src.core.logger import ATTENTION, loggers

class HandleAwait(Handler):
    """
    the handler to handle await(AST_YIELD)
    """
    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        from src.plugins.manager_instance import internal_manager

        flags = self.G.get_node_attr(self.node_id).get('flags:string[]')
        promises = internal_manager.dispatch_node(self.G.get_ordered_ast_child_nodes(self.node_id)[0])
        loggers.main_logger.info(f'promises obj, AST: {self.node_id}, promises: {promises} {flags}')

        # if flags == 'JS_AWAIT_EXPRESSION':
        #     return NodeHandleResult(ast_node=self.node_id, obj_nodes=promises.obj_nodes, used_objs=promises.obj_nodes, callback=get_df_callback(self.G))

        # call promise.then
        returned_objs = set()

        if flags == 'JS_SPREAD_ELEMENT':
            # e.g., [...Array(6)]
            returned_objs.update(promises.obj_nodes)
        else:
            for promise in promises.obj_nodes:
                await_resolved = await_then(G=self.G, promise = promise)
                returned_objs.update(await_resolved.obj_nodes)

        loggers.main_logger.info(f'await returns objs node {returned_objs}, ast_node {self.node_id}')
        return NodeHandleResult(ast_node=self.node_id,
                                obj_nodes=list(returned_objs),
                                used_objs=promises.obj_nodes,
                                callback=get_df_callback(self.G))
    

def await_then(G: Graph, promise):
    obj_nodes = set()
    fulfilled_with = G.get_node_attr(promise).get('fulfilled_with')
    if fulfilled_with:
        obj_nodes.update(fulfilled_with.obj_nodes)
    else:
        # e.g., const foo = 1; await foo;
        obj_nodes.add(promise)
    return NodeHandleResult(obj_nodes=list(obj_nodes))
