from src.core.jsx_constant import DOM_TAG_AND_ATTR_PAIRS, JSX_DOM_events, JSX_Nodes
from src.core.logger import *
from src.core.graph import Graph
from src.core.utils import NodeHandleResult, ExtraInfo
from src.plugins.handler import Handler
from src.plugins.internal.handlers.functions import call_function
from src.plugins.internal.utils import to_obj_nodes, wildcard, get_df_callback
from ..utils import get_df_callback, to_obj_nodes


class HandleJSXAttribute(Handler):

    def __init__(self, G, node_id, extra=None):
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        r = ast_jsx_attribute(self.G, self.node_id, self.extra)
        return r


def ast_jsx_attribute(G: Graph, ast_node, extra):
    from src.plugins.manager_instance import internal_manager
    if G.finished:
        return NodeHandleResult()

    attr_children = G.get_ordered_ast_child_nodes(ast_node)
    if len(attr_children) != 2:
        raise ValueError(f'Unsupported JSX Attribute AST Format, AST Node: {ast_node} {attr_children}')

    left_child, right_child = attr_children
    left_child_attr = G.get_node_attr(left_child)
    attr_name = left_child_attr['code']

    if attr_name == 'JSXSpreadAttribute':
        return handle_spread_attribute(G, extra.parent_component, ast_node,  attr_name, right_child, extra)

    attr_node = G.add_jsx_attribute_node(ast_node, attr_name)

    if extra.parent_component:
        component_node = extra.parent_component
        loggers.main_logger.info(f'Added JSX Attr Data flow edge From {attr_node} to {component_node}')
        G.add_jsx_data_flow_edge(attr_node, component_node)

    # TODO: Check if there will be other values when testing more cases.
    right_expression_container = G.get_ordered_ast_child_nodes(right_child)[0]

    right_objs = []
    # if right_expression_container has children, it's an expression; otherwise, it's a literal, e.g., a string
    if G.get_ordered_ast_child_nodes(right_expression_container):
        right_expression = G.get_ordered_ast_child_nodes(right_expression_container)[0]
        handled_right = internal_manager.dispatch_node(right_expression, extra)
        right_objs = to_obj_nodes(G, handled_right, right_expression)
        for obj in right_objs:
            G.add_jsx_data_flow_edge(obj, attr_node)
    else:
        # handle literal
        handled_right = internal_manager.dispatch_node(right_expression_container, extra)
        right_objs = to_obj_nodes(G, handled_right, right_expression_container)
        for obj in right_objs:
            G.add_jsx_data_flow_edge(obj, attr_node)

    loggers.main_logger.info(f'handling jsx attribute {attr_name}, {handled_right}')

    props_node = None

    handle_dom_events_attribute(G=G, attr_name=attr_name, right_objs=right_objs, extra=extra)

    component_node = None
    if extra.parent_component:
        component_node = extra.parent_component

    # TODO: check ref.current.value
    if attr_name == 'ref' and component_node:
        comp_attr = G.get_node_attr(component_node)
        comp_name = comp_attr['name']
        component_label = G.get_node_attr(component_node)['labels:label']
        if component_label == JSX_Nodes.JSX_DOM and right_objs and comp_name in ['input', 'select']:
            # use ref.current.value to access the value of a DOM element, for example, input, select
            ref_obj = right_objs[0]
            # it is possible the ref is not obtained through useRef(), e.g., from a thried-party library. So we may not be able to get the ref.current obj.
            ref_current_props = G.get_prop_obj_nodes(parent_obj=ref_obj, prop_name='current')
            if ref_current_props:
                loggers.main_logger.info(f'ref_current_props: {ref_current_props}')
                ref_current_obj = ref_current_props[0]
                ref_current_value_obj = G.add_obj_node(ast_node=ast_node, js_type='object', value=wildcard)
                G.set_node_attr(ref_current_value_obj, ('tainted', True))
                loggers.main_logger.info(f'ref current value is marked as tainted: {ref_current_value_obj}')
                G.add_obj_as_prop(prop_name='value', js_type='object', parent_obj=ref_current_obj, tobe_added_obj=ref_current_value_obj)

    check_dom_xss_attrs(G, component_node=component_node, attr_name=attr_name, right_objs=right_objs, attr_node=attr_node)

    if component_node:
        props_node = G.get_or_add_jsx_props_node(component_node=component_node, ast_node=ast_node)
        for right_obj in right_objs:
            right_obj_attr = G.get_node_attr(right_obj)
            G.add_obj_as_prop(prop_name=attr_name, js_type='object', parent_obj=props_node, tobe_added_obj=right_obj)
            loggers.main_logger.info(f'Added JSX Attr: component_node: {component_node}, props Node: {props_node}, props attr name: {attr_name}, {right_obj} {right_obj_attr}')

    return NodeHandleResult(obj_nodes=right_objs, name_nodes=handled_right.name_nodes, name=attr_name,  callback=get_df_callback(G), jsx_nodes=[attr_node], used_objs=list([props_node] if props_node else []))


def check_dom_xss_attrs(G, component_node, attr_name, right_objs, attr_node):
    for (dom_tag, dom_attr) in DOM_TAG_AND_ATTR_PAIRS:
        if attr_name == dom_attr and component_node:
            comp_attr = G.get_node_attr(component_node)
            comp_name = comp_attr['name']
            component_label = comp_attr['labels:label']
            if component_label == JSX_Nodes.JSX_DOM and right_objs:
                for right_obj in right_objs:
                    right_obj_attr = G.get_node_attr(right_obj)
                    if comp_name == dom_tag:
                        G.jsx_tainted_objs.append(component_node)

    if attr_name == 'html' and component_node:
        comp_attr = G.get_node_attr(component_node)
        comp_name = comp_attr['name']
        component_label = comp_attr['labels:label']
        if component_label == JSX_Nodes.JSX_Component and right_objs:
            for right_obj in right_objs:
                if comp_name == 'DangerouslySetHtmlContent':
                    G.jsx_tainted_objs.append(component_node)


def handle_spread_attribute(G: Graph, component_node, ast_node, attr_name, right_child, extra):
    from src.plugins.manager_instance import internal_manager
    if attr_name != 'JSXSpreadAttribute' or not component_node:
        return NodeHandleResult(obj_nodes=[], name_nodes=[])

    component_node_attr = G.get_node_attr
    right_expression_container = G.get_ordered_ast_child_nodes(right_child)[0]

    handled_right = internal_manager.dispatch_node(right_expression_container, extra)
    right_objs = to_obj_nodes(G, handled_right, right_expression_container)

    comp_node_attr = G.get_node_attr(component_node)
    props_node = G.get_or_add_jsx_props_node(component_node=component_node, ast_node=ast_node)
    spread_for_dom = False
    tained_right_objs = []
    for right_obj in right_objs:
        right_obj_attr = G.get_node_attr(right_obj)
        if right_obj_attr.get('tainted') == True and right_obj_attr.get('code') == wildcard and right_obj_attr.get('type') == 'object':
            G.set_node_attr(props_node, ('tainted', True))
            G.set_node_attr(props_node, ('code', wildcard))
            if comp_node_attr:
                spread_for_dom = True
                tained_right_objs.append(right_obj)
    if spread_for_dom:
        attr_node = G.add_jsx_attribute_node(ast_node=ast_node, attr_name='*')
        G.add_jsx_data_flow_edge(attr_node, component_node)
        for obj in tained_right_objs:
            G.add_jsx_data_flow_edge(obj, attr_node)
        G.jsx_tainted_objs.append(component_node)

    return NodeHandleResult(obj_nodes=right_objs, name_nodes=handled_right.name_nodes, jsx_nodes=[], used_objs=list([props_node] if props_node else []))


def handle_dom_events_attribute(G: Graph, attr_name, right_objs, extra):
    if attr_name in JSX_DOM_events:
        func_objs = right_objs
        for func_obj in func_objs:
            node_attr = G.get_node_attr(func_obj)
            if node_attr['type'] != 'function':
                continue
        parent_component_attr = G.get_node_attr(extra.parent_component)
        loggers.main_logger.info(f'jsx attribute dom events {attr_name} {node_attr} {extra.parent_component} {parent_component_attr}')

        def trigger_dom_events(parent_component_attr=parent_component_attr):
            mark_fake_args = True
            if parent_component_attr and parent_component_attr.get('labels:label') == JSX_Nodes.JSX_DOM and parent_component_attr.get('name') == 'button':
                mark_fake_args = False
            call_function(G, func_objs, extra=ExtraInfo(), args=[], is_new=False, mark_fake_args=mark_fake_args)

        G.dom_events_queue.append(trigger_dom_events)
