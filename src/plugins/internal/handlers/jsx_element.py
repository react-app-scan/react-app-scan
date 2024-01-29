from src.core.jsx_constant import JSX_CLASS_MOUNTING_FUNCTION, JSX_CLASS_UPDATING_FUNCTION
from src.plugins.internal.handlers.functions import call_function
from src.plugins.internal.handlers.jsx_attribute import ast_jsx_attribute
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler
from src.core.utils import wildcard


class HandleJSXElement(Handler):

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
    loggers.main_logger.log(ATTENTION, 'Handling JSX Element {}, children {}'.format(ast_node, jsx_element_children))

    jsx_opening_element = jsx_element_children[0]
    jsx_element_identifier = G.get_ordered_ast_child_nodes(jsx_opening_element)[0]

    identifier_attr = G.get_node_attr(jsx_element_identifier)
    component_name = identifier_attr['code']
    loggers.main_logger.log(ATTENTION, f'Handling JSX Element component_name {component_name} {jsx_element_identifier} {identifier_attr}')

    is_react_component = component_name and (not component_name[0].islower()) and component_name != 'React.Fragment'

    # We call the "React Component Node" and "DOM Node" as component_node
    component_node = None

    if is_react_component:
        component_node = G.add_jsx_component_node(ast_node, component_name)
        G.cur_jsx_component = component_node
    else:
        component_node = G.add_dom_node(ast_node, component_name)
        G.cur_jsx_component = None

    if G.parent_component and (G.parent_component is not component_node):
        G.add_jsx_parent_of_edge(G.parent_component, component_node)

    if component_node:
        G.parent_component = component_node

    jsx_attr_objs = []
    if len(G.get_ordered_ast_child_nodes(jsx_opening_element)) > 1:
        jsx_attributes = G.get_ordered_ast_child_nodes(jsx_opening_element)[1]
        jsx_attributes_children_ast_list = G.get_ordered_ast_child_nodes(jsx_attributes)
        for jsx_attribute in jsx_attributes_children_ast_list:
            r = ast_jsx_attribute(G, ast_node=jsx_attribute, extra=ExtraInfo(extra, parent_component=component_node))
            jsx_attr_objs.append(r)

    props_obj = []
    if jsx_attr_objs and is_react_component:
        props_obj = G.get_or_add_jsx_props_node(component_node=component_node, ast_node=ast_node)

    for ast_child in jsx_element_children:
        G.cur_stmt = ast_child
        internal_manager.dispatch_node(ast_child, ExtraInfo(extra, parent_component=component_node))

    if is_react_component:
        component_name_node = G.get_name_node(var_name=component_name)
        component_def_node_list = G.get_objs_by_name_node(name_node=component_name_node)
        cur_comp_def_obj_list = component_def_node_list
        for comp_def_obj_node in cur_comp_def_obj_list:
            G.add_jsx_component_def_edge(component_node, comp_def_obj_node)

        valid_def_comp_list = []
        for comp_def_obj in cur_comp_def_obj_list:
            comp_def_obj_attr = G.get_node_attr(comp_def_obj)
            if comp_def_obj_attr.get('code') == wildcard:
                continue
            else:
                valid_def_comp_list.append(comp_def_obj)

        if cur_comp_def_obj_list:
            # function components
            args = []
            if jsx_attr_objs:
                for jsx_attr in jsx_attr_objs:
                    for obj_node in jsx_attr.obj_nodes:
                        G.add_obj_as_prop(prop_name=jsx_attr.name, js_type='object', parent_obj=props_obj, tobe_added_obj=obj_node)
                args = [NodeHandleResult(obj_nodes=[props_obj], name='props')]
            returned_result, newed_objs = call_function(G, cur_comp_def_obj_list, extra=extra, args=args, is_new=False, mark_fake_args=False)

            # class components
            for cur_comp_def_obj in cur_comp_def_obj_list:
                prototypes = G.get_prop_obj_nodes(cur_comp_def_obj, 'prototype', branches=extra.branches)
                if not prototypes:
                    continue
                for p in prototypes:
                    mouting_funcs = []
                    updating_funcs = []
                    for func_name in JSX_CLASS_MOUNTING_FUNCTION:
                        mouting_funcs += G.get_prop_obj_nodes(parent_obj=p, prop_name=func_name, branches=extra.branches)
                    for func_name in JSX_CLASS_UPDATING_FUNCTION:
                        updating_funcs += G.get_prop_obj_nodes(parent_obj=p, prop_name=func_name, branches=extra.branches)

                    render_method_objs = G.get_prop_obj_nodes(parent_obj=p, prop_name='render', branches=extra.branches)
                    componentWillUnmount_objs = G.get_prop_obj_nodes(parent_obj=p, prop_name='componentWillUnmount', branches=extra.branches)
                    G.cleanup_funcs.extend(componentWillUnmount_objs)
                    class_this_obj = None
                    for render_method_obj in render_method_objs:
                        if not jsx_attr_objs:
                            continue
                        render_method_obj_attr = G.get_node_attr(render_method_obj)
                        class_this_objs = render_method_obj_attr.get('parent_scope_this')
                        if not class_this_objs:
                            continue
                        class_this_obj = class_this_objs[0]
                    if class_this_obj:
                        G.add_obj_as_prop(prop_name='props', js_type='object', parent_obj=class_this_obj, tobe_added_obj=props_obj)
                        class_this_state_objs = G.get_prop_obj_nodes(parent_obj=class_this_obj, prop_name='state')
                        class_this_state_name_node = G.get_prop_name_node('state', parent_obj=class_this_obj)

                        def class_set_state(G: Graph, caller_ast, extra, _, *args):
                            for new_state_obj in args[0].obj_nodes:
                                G.add_obj_to_name_node(name_node=class_this_state_name_node, tobe_added_obj=new_state_obj)
                            G.comp_update_queue.append(component_node)
                            return NodeHandleResult()

                        G.add_blank_func_as_prop(func_name='setState', parent_obj=class_this_obj, python_func=class_set_state)
                        loggers.main_logger.info(f'class_this_objs: {class_this_obj} {props_obj}')
                    if not G.updating_phase:
                        call_function(G, mouting_funcs, extra=extra, args=args, is_new=False, mark_fake_args=False, this=NodeHandleResult(obj_nodes=[class_this_obj]))
                    else:
                        call_function(G, updating_funcs, extra=extra, args=args, is_new=False, mark_fake_args=False, this=NodeHandleResult(obj_nodes=[class_this_obj]))

        if len(valid_def_comp_list) == 0:
            G.set_node_attr(component_node, ('value', wildcard))

    return NodeHandleResult(jsx_nodes=[component_node])


def update_jsx_comp(G: Graph, comp_node):
    if not comp_node:
        raise ValueError('Component node is missing.')
    comp_def = G.get_jsx_component_def_node(component_node=comp_node)
    if not comp_def:
        return
    G.cur_jsx_component = comp_node
    comp_props = G.get_jsx_props_node(component_node=comp_node)
    call_func_args = [NodeHandleResult(name='props', obj_nodes=[comp_props])] if comp_props else []
    loggers.main_logger.info(f'Updating JSX Component: {comp_node}')
    call_function(G, [comp_def], extra=ExtraInfo(), args=call_func_args, is_new=False, mark_fake_args=False)
