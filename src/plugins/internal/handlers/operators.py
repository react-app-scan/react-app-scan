from src.plugins.internal.handlers.functions import call_function
from src.plugins.internal.handlers.assign_op import handle_op_by_objs
from src.core.jsx_constant import JSX_Label_Key, JSX_Labels
from src.core.graph import Graph
from src.core.utils import *
from ..utils import add_contributes_to, to_obj_nodes, get_df_callback, to_values, check_condition
from src.core.logger import ATTENTION, loggers
from . import vars
from src.plugins.handler import Handler
from src.plugins.internal.handlers.vars import handle_var
import sty
from src.core.checker import obj_traceback, print_success_pathes
from src.core.options import options

class HandleBinaryOP(Handler):
    """
    handle the AST_BINARY_OP
    """
    def process(self):
        node_id = self.node_id
        G = self.G
        extra = self.extra
        cur_node_attr = G.get_node_attr(node_id)
        handle_node = self.internal_manager.dispatch_node

        left_child, right_child = G.get_ordered_ast_child_nodes(node_id)
        flag = cur_node_attr.get('flags:string[]')
        if flag == 'BINARY_BOOL_OR':
            # TODO: add value check to filter out false values
            handled_left = handle_node(left_child, extra)
            handled_right = handle_node(right_child, extra)
            now_objs = list(set(to_obj_nodes(G, handled_left, node_id)
                + to_obj_nodes(G, handled_right, node_id)))
            return NodeHandleResult(obj_nodes=now_objs)
        elif flag in ['BINARY_ADD', 'BINARY_SUB']:
            loggers.main_logger.info('handle here')
            return handle_op_by_objs(G, node_id, extra, manager=self.internal_manager)
        elif flag in ['BINARY_BOOL_OR', 'BINARY_BOOL_AND', 'BINARY_IS_EQUAL',
            'BINARY_IS_IDENTICAL', 'BINARY_IS_NOT_EQUAL',
            'BINARY_IS_NOT_IDENTICAL', 'BINARY_IS_SMALLER',
            'BINARY_IS_GREATER', 'BINARY_IS_SMALLER_OR_EQUAL',
            'BINARY_IS_GREATER_OR_EQUAL']:
            p, d = check_condition(G, node_id, extra)
            if not d:
                return NodeHandleResult(values=[wildcard], 
                                        obj_nodes=[G.true_obj, G.false_obj])
            elif p == 1:
                return NodeHandleResult(obj_nodes=[G.true_obj])
            elif p == 0:
                return NodeHandleResult(obj_nodes=[G.false_obj])
            else:
                return NodeHandleResult(obj_nodes=[G.true_obj, G.false_obj])
        else:
            # could be others like '', return true or false
            return NodeHandleResult(obj_nodes=[G.true_obj, G.false_obj])

class HandleAssign(Handler):

    def process(self, right_override=None):
        '''
        Handle assignment statement.
        '''
        extra = self.extra
        ast_node = self.node_id
        G = self.G
        if extra is None:
            extra = ExtraInfo()
        # get AST children (left and right sides)
        ast_children = G.get_ordered_ast_child_nodes(ast_node)
        loggers.main_logger.log(ATTENTION, f'processing assign: {self.node_id}, ast_children: {ast_children}')
        try:
            left, right = ast_children
        except ValueError:
            # if only have left side
            return self.internal_manager.dispatch_node(ast_children[0], extra)

        # get branch tags
        branches = extra.branches if extra else BranchTagContainer()

        # recursively handle both sides
        # handle right first
        if right_override is None:
            handled_right = \
                self.internal_manager.dispatch_node(right, ExtraInfo(extra, side='right'))
        else:
            handled_right = right_override

        if G.get_node_attr(left).get('type') == 'AST_ARRAY':
            # destructuring assignment
            # handle left item by item
            children = G.get_ordered_ast_child_nodes(left)
            if G.get_node_attr(left).get('flags:string[]') == 'JS_OBJECT':
                # ObjectPattern assignments
                added_obj = G.add_obj_node(ast_node=ast_node, js_type='object')
                for child in children:
                    child_attr = G.get_node_attr(child)
                    if child_attr['type'] == 'RestElement':
                        # ast_children = 
                        value = G.get_ordered_ast_child_nodes(child)[0]
                        key = G.get_ordered_ast_child_nodes(value)[0]
                    else:
                        value, key = G.get_ordered_ast_child_nodes(child)
                    if G.get_node_attr(value).get('type') == 'AST_ARRAY':
                        handled_left = NodeHandleResult()
                        for ast_array_elem in G.get_ordered_ast_child_nodes(value):
                            res = handle_var(G, ast_array_elem, side='left', extra=extra)
                            handled_left.obj_nodes += res.obj_nodes
                            handled_left.name_nodes += res.name_nodes
                    else:
                        handled_left = handle_var(G, value, side='left', extra=extra)
                    _key = G.get_name_from_child(key)
                    for obj in handled_right.obj_nodes:
                        # right side obj is a wildcard obj
                        obj_attr = G.get_node_attr(obj)
                        if 'code' in obj_attr and obj_attr['code'] == wildcard:
                            do_assign(G, handled_left, NodeHandleResult(obj_nodes=handled_right.obj_nodes), branches, ast_node)
                        else:
                            prop_obj_nodes= G.get_prop_obj_nodes(parent_obj=obj,
                                prop_name=_key, branches=branches)
                            loggers.main_logger.info(f'prop_obj_nodes: {prop_obj_nodes} {obj} {obj_attr} {_key}')
                            for o in prop_obj_nodes:
                                G.add_obj_as_prop(parent_obj=added_obj,
                                    prop_name=_key, tobe_added_obj=o)
                            do_assign(G, handled_left, NodeHandleResult(
                                obj_nodes=prop_obj_nodes), branches, ast_node)
                return NodeHandleResult(obj_nodes=[added_obj])
            elif G.get_node_attr(left).get('type') == 'AST_OBJECT_PATTERN':
                loggers.main_logger.info(f'AST_OBJECT_PATTERN: {left}')

            else:
                # ArrayPattern assignments
                added_obj = G.add_obj_node(ast_node=ast_node, js_type='array')
                for i, child in enumerate(children):
                    handled_left = handle_var(G, child, side='left', extra=extra)
                    for obj in handled_right.obj_nodes:
                        prop_obj_nodes= G.get_prop_obj_nodes(parent_obj=obj, prop_name=str(i), branches=branches)
                        for o in prop_obj_nodes:
                            G.add_obj_as_prop(parent_obj=added_obj, prop_name=str(i), tobe_added_obj=o)
                        do_assign(G, handled_left, NodeHandleResult(obj_nodes=prop_obj_nodes), branches, ast_node)
                G.add_obj_as_prop(parent_obj=added_obj, prop_name='length', js_type='number', value=len(children), ast_node=ast_node)

                return NodeHandleResult(obj_nodes=[added_obj])
        else:
            # normal assignment
            handled_left = self.internal_manager.dispatch_node(left, ExtraInfo(extra, side='left'))
            # it happends that the handled
            # set function name
            name = handled_left.name
            if name and G.get_node_attr(right).get('type') in ['AST_FUNC_DECL', 'AST_CLOSURE', 'AST_METHOD']:
                for func_obj in handled_right.obj_nodes:
                    old_name = G.get_node_attr(func_obj).get('name')
                    if not old_name or old_name == '{closure}':
                        G.set_node_attr(func_obj, ('name', name))
            loggers.main_logger.info(f'handled_right: {handled_right}')
            assert type(handled_right) == NodeHandleResult

            return do_assign(G, handled_left, handled_right, branches, ast_node)

def do_assign(G: Graph, handled_left, handled_right, branches=None, ast_node=None):
    logger = loggers.main_logger
    if branches is None:
        branches = BranchTagContainer()

    if not handled_left:
        loggers.main_logger.warning("Left side handling error at statement {}".format(ast_node))
        return NodeHandleResult()

    if not handled_right:
        loggers.main_logger.warning("Right side handling error at statement {}".format(ast_node))
        return NodeHandleResult()

    right_objs = to_obj_nodes(G, handled_right, ast_node)

    if not right_objs:
        logger.debug("Right OBJ not found")
        right_objs = [G.undefined_obj]

    # for OPGen_TAINTED_VAR mark tainted
    if handled_left.name and "OPGen_TAINTED_VAR" in handled_left.name:
        for obj in right_objs:
            G.set_node_attr(obj, ('tainted', True))
            G.set_node_attr(obj, ('code', wildcard))

    # returned objects for serial assignment (e.g. a = b = c)
    returned_objs = []
    right_tainted = len(list(filter(lambda x: \
            G.get_node_attr(x).get('tainted') is True, right_objs))) != 0

    if G.check_useRef:
        check_dom_ref_innerHTML(G, handled_left, right_objs, ast_node)
    
    check_setting_location_href(G, handled_left, right_objs, ast_node)

    check_dom_event_callback(G, handled_left, right_objs, ast_node)

    check_window_onmessage(G, handled_left, right_objs, ast_node)

    if G.check_ipt:
        if handled_left.parent_objs is not None:
            # the left part is property
            if handled_left.name_tainted and right_tainted:
                # name node tainted and it's a property assign
                # mark the parent object as prop_tainted
                for parent_obj in handled_left.parent_objs:
                    G.set_node_attr(parent_obj, ('prop_tainted', True))

    if G.check_proto_pollution:
        loggers.main_logger.info(f"Checking proto pollution, name tainted: {handled_left.name_tainted}"\
            f" parent is proto: {handled_left.parent_is_proto}")
    if G.check_proto_pollution and (handled_left.name_tainted and handled_left.parent_is_proto):
        flag1 = False
        flag2 = False
        tainted_right_objs = []
        tainted_key_objs = []

        for obj in right_objs:
            if G.get_node_attr(obj).get('tainted'):
                tainted_right_objs.append(obj)
                flag2 = True

        key_objs = handled_left.key_objs
        for obj in key_objs:
            if G.get_node_attr(obj).get('tainted'):
                tainted_key_objs.append(obj)

        loggers.main_logger.info(f"right tainted: {flag2}")
        if flag2:
            #loggers.res_logger.info(f"Prototype pollution detected in {G.package_name}")
            name_node_log = [('{}: {}'.format(x, repr(G.get_node_attr(x)
                .get('name')))) for x in handled_left.name_nodes]
            print(sty.fg.li_green + sty.ef.inverse +
                'Prototype pollution detected at node {} (Line {})'
                .format(ast_node, G.get_node_attr(ast_node).get('lineno:int'))
                 + sty.rs.all)

            success_pathes_val = []
            success_pathes_key = []
            proto_map_pathes = []

            # find the value path
            for right_obj in tainted_right_objs:
                _, _ast_pathes, _ = obj_traceback(G, right_obj)
                # since ast_pathes does not include the cur ast
                for ast_path in _ast_pathes:
                    ast_path.reverse()
                    ast_path.append(ast_node)
                    success_pathes_val.append(ast_path)
            # find the key2 path
            for left_obj in tainted_key_objs:
                _, _ast_pathes, _ = obj_traceback(G, left_obj)
                # since ast_pathes does not include the cur ast
                print(_ast_pathes, left_obj, ast_node)
                for ast_path in _ast_pathes:
                    ast_path.reverse()
                    ast_path.append(ast_node)
                    success_pathes_key.append(ast_path)

            # find which __proto__
            built_in_proto = set()
            for obj in handled_left.parent_objs:
                if obj in G.builtin_prototypes:
                    built_in_proto.add(obj)

            for obj in built_in_proto:
                cur_attr = G.get_node_attr(obj)
                proto_map_pathes.append([obj, ast_node])

            G.proto_pollution.add(ast_node)
            G.detection_res["proto_pollution"].add(G.package_name)

            # pathes = traceback(G, "proto_pollution", ast_node)
            print_success_pathes(G, success_pathes_val, color="red")
            print("Val success", success_pathes_val)
            print_success_pathes(G, success_pathes_key, color="green")
            print_success_pathes(G, proto_map_pathes, color="blue")
            print("Proto map", proto_map_pathes)

            logger.warning(sty.fg.li_red + sty.ef.inverse +
                'Possible prototype pollution at node {} (Line {}), '
                'trying to assign {} to name node {}'
                .format(ast_node, G.get_node_attr(ast_node).get('lineno:int'),
                right_objs, ', '.join(name_node_log)) + sty.rs.all)

            logger.debug(f'Pollutable objs: {G.pollutable_objs}')
            logger.debug(f'Pollutable NN: {G.pollutable_name_nodes}')
            if G.exit_when_found and G.detection_res[G.vul_type]:
                G.finished = True
            # skip doing the assignment
            return NodeHandleResult()

    if not handled_right.obj_nodes and handled_right.terminated:
        # skip doing the assignment
        return NodeHandleResult()

    # do the assignment
    for name_node in handled_left.name_nodes:
        # nn_for_tags = G.get_node_attr(name_node).get('for_tags')
        # if not nn_for_tags: # empty array or None
        G.assign_obj_nodes_to_name_node(name_node, right_objs,
            branches=branches)
        returned_objs.extend(right_objs)

    return NodeHandleResult(obj_nodes=right_objs,
        name_nodes=handled_left.name_nodes, # used_objs=used_objs,
        callback=get_df_callback(G))


def check_dom_ref_innerHTML(G, handled_left, right_objs, ast_node):
    right_tainted = len(list(filter(lambda x: G.get_node_attr(x).get('tainted') is True, right_objs))) != 0
    if handled_left.parent_objs is None:
        return
    left_name = handled_left.name
    if left_name == 'a.href' and right_tainted:
        print(f"{sty.fg.li_green}{sty.ef.inverse}source flows to a.href {ast_node} (Line {G.get_node_attr(ast_node).get('lineno:int')}){sty.rs.all}")
    if not left_name or not left_name.endswith('innerHTML'):
        return
    for p_obj in handled_left.parent_objs:
        p_attr = G.get_node_attr(p_obj)
        if JSX_Label_Key in p_attr and p_attr[JSX_Label_Key] == JSX_Labels.JSX_REF_CURRENT:
            print(f'found useRef.innerHTML case')
            if right_tainted:
                print(f"{sty.fg.li_green}{sty.ef.inverse}useRef detected at node {ast_node} (Line {G.get_node_attr(ast_node).get('lineno:int')}){sty.rs.all}")
            G.jsx_tainted_objs.append(p_obj)
            useRef_current = p_obj
            if useRef_current:
                for obj in right_objs:
                    add_contributes_to(G, [obj], useRef_current)

def check_setting_location_href(G, handled_left, right_objs, ast_node):
    right_tainted = len(list(filter(lambda x: G.get_node_attr(x).get('tainted') is True, right_objs))) != 0
    if handled_left.parent_objs is None:
        return
    left_name = handled_left.name
    if not left_name or not left_name == ('window.location.href'):
        return

    for obj_node in handled_left.obj_nodes:
        obj_attr = G.get_node_attr(obj_node)
        if obj_attr.get('location_source') == True and right_tainted:
            print(f"{sty.fg.li_green}{sty.ef.inverse} attack path[0/n]: setting location.href detected at ast node: {ast_node} (Line {G.get_node_attr(ast_node).get('lineno:int')}){sty.rs.all}")
            for right_obj_tainted in right_objs:
                G.jsx_tainted_objs.append(right_obj_tainted)
                G.set_node_attr(right_obj_tainted, ('callee_of_dom_op', True))
                G.check_window_open = True

def check_dom_event_callback(G, handled_left, right_objs, ast_node):
    right_tainted = len(list(filter(lambda x: G.get_node_attr(x).get('tainted') is True, right_objs))) != 0
    if handled_left.parent_objs is None:
        return
    left_name = handled_left.name
    if not left_name or not left_name.endswith('onmessage'):
        return
    def trigger_dom_events():
        loggers.main_logger.info(f'triggering dom events onmessage, call back function: {right_objs}')
        call_function(G, right_objs, extra=ExtraInfo(), args=[], is_new=False, mark_fake_args=True)
    G.dom_events_queue.append(trigger_dom_events)


def check_window_onmessage(G, handled_left, right_objs, ast_node):
    left_name = handled_left.name
    if not left_name or not (left_name == 'window.onmessage'):
        return
    def trigger_dom_events():
        call_function(G, right_objs, extra=ExtraInfo(), args=[], is_new=False, mark_fake_args=True)
    G.dom_events_queue.append(trigger_dom_events)