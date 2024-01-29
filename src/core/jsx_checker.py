from .trace_rule import TraceRule
from .vul_func_lists import Sinks
from .logger import ATTENTION, loggers
import sty
from src.core.options import options
from .graph import Graph
from src.core.jsx_constant import JSX_Edges, JSX_Label_Key, JSX_Nodes
import sys
import os


def jsx_get_path_ast(G: Graph, path, caller=None):
    ast_node_map = {}
    ast_path_list = []
    for node in path:
        if node is None:
            return ""
        ast_node = G.get_obj_def_ast_node(node)
        if not ast_node:
            node_attr = G.get_node_attr(node)
            if node_attr['type'] == 'jsx' or JSX_Label_Key in node_attr:
                ast_node = G.get_jsx_def_ast_node(node)
                if not ast_node:
                    sys.stderr.write(f'[Error] can not find ast nodes for JSX node {node}')
                    loggers.error_logger.info(f'[Error] can not find ast nodes for JSX node {node}')
        if ast_node:
            ast_node_map[ast_node] = node
            node = ast_node
        ast_path_list.append(node)
    return ast_path_list


def jsx_get_path_text(G: Graph, ast_path, caller=None):
    """
    get the code by ast number
    Args:
        G: the graph
        path: the path with ast nodes
    Return:
        str: a string with text path
    """
    res_path = ""
    cur_path_str = ""

    for node in ast_path:
        cur_node_attr = G.get_node_attr(node)

        content = None
        if cur_node_attr.get('type') == 'object':
            continue
        if cur_node_attr.get('lineno:int') is None:
            continue

        if os.path.isfile(options.input_file):
            node_file_path = options.input_file
        else:
            node_file_path = G.get_node_file_path(node)

        relative_node_file_path = os.path.relpath(node_file_path, options.input_file)
        cur_path_str += "$FilePath$ {}\n".format(relative_node_file_path)
        try:
            content = G.get_node_file_content(node, file_path=node_file_path)
        except Exception as e:
            print(f'can not get the file content for {node}', e)

        if cur_node_attr['type'] == 'object':
            if 'code' in cur_node_attr:
                cur_path_str += "{}\n".format(cur_node_attr['code'])
                continue
            else:
                cur_path_str += "{}\n"
                continue

        start_lineno = int(cur_node_attr['lineno:int'])
        end_lineno = int(cur_node_attr['endlineno:int'] or start_lineno)

        if content is not None:
            cur_path_str += f"Line {start_lineno} ast_node {node} \t{''.join(content[start_lineno:end_lineno + 1])}"

    res_path += "==========================\n"
    res_path += cur_path_str
    res_path += "==========================\n"
    return res_path


def jsx_traceback(G: Graph, vul_type, start_node=None):
    """
    traceback from the leak point, the edge is OBJ_REACHES
    Args:
        G: the graph
        vul_type: the type of vulernability, listed below

    Return:
        the paths include the objs,
        the string description of paths,
        the list of callers,
    """
    res_path = ""
    ret_pathes = []
    caller_list = []

    sink_funcs = Sinks()
    exploit_func_list = sink_funcs.get_sinks_by_vul_type(vul_type)

    loggers.main_logger.log(ATTENTION, 'exploit_func_list' + str(exploit_func_list))

    start_node_list = set()
    if 'dangerouslySetInnerHTML' in exploit_func_list:
        jsx_attr_node_list = G.get_node_by_attr('name', 'dangerouslySetInnerHTML')
        filtered_list = []
        for n in jsx_attr_node_list:
            if G.get_node_attr(n).get('type') == 'NAMENODE':
                continue
            filtered_list.append(n)
        jsx_attr_node_list = filtered_list
        loggers.main_logger.log(ATTENTION, 'jsx_attr_node_list' + str(jsx_attr_node_list))
        start_node_list.update(jsx_attr_node_list)

    if G.jsx_tainted_objs:
        start_node_list.update(G.jsx_tainted_objs)

    loggers.main_logger.info(f'start_node_list: {start_node_list}')
    start_node_list = list(start_node_list)
    start_node_list = sorted(start_node_list)
    for start_node in start_node_list:
        pathes = G._dfs_upper_by_multi_edge_types(start_node, ["CONTRIBUTES_TO", JSX_Edges.JSX_DATA_FLOW, JSX_Edges.JSX_PARENT_OF, "OBJ_TO_PROP", "NAME_TO_OBJ"])
        for path in pathes:
            loggers.main_logger.log(ATTENTION, 'pathlist: {}'.format(path))

        for path in pathes:
            ret_pathes.append(path)
            path.reverse()

    return ret_pathes, res_path, caller_list


def jsx_do_vul_checking(G, rule_list, pathes):
    """
    checking the vuleralbilities in the pathes

    Args:
        G: the graph object
        rule_list: a list of paires, (rule_function, args of rule_functions)
        pathes: the possible pathes
    Returns:

    """
    trace_rules = []
    for rule in rule_list:
        trace_rules.append(TraceRule(rule[0], rule[1], G))

    success_pathes = []
    flag = True
    for path in pathes:
        flag = True
        loggers.main_logger.info(f'checking path: {path}')
        for index, trace_rule in enumerate(trace_rules):
            if not trace_rule.check(path):
                loggers.main_logger.info(f'rule: {trace_rule.key} not passed')
                flag = False
                break
            else:
                loggers.main_logger.info(f'rule: {trace_rule.key} passed')
        if flag:
            loggers.main_logger.info('all passed')
            success_pathes.append(path)
    return success_pathes


def jsx_vul_checking(G: Graph, pathes, vul_type):
    """
    picking the pathes which satisfy the xss
    Args:
        G: the Graph
        pathes: the possible pathes
    return:
        a list of xss pathes
    """
    sink_funcs = Sinks()
    xss_rule_lists = [
        [
            ('jsx_has_user_input', None),
            ('jsx_not_sanitized', None),
            ('end_with_jsx_attribute', sink_funcs.get_sinks_by_vul_type('xss')),
        ],
    ]

    if G.check_useRef:
        xss_rule_lists.append([('jsx_has_user_input', None), ('jsx_has_dom_ref', None), ('jsx_not_sanitized', None)])

    if G.check_a_href:
        xss_rule_lists.append([('jsx_has_user_input', None), ('jsx_has_dom_xss_pair', None), ('jsx_has_no_indirect_src', None), ('jsx_not_sanitized', None)])

    xss_rule_lists.append([('jsx_has_user_input', None), ('jsx_has_spread_attrs', None), ('jsx_has_no_indirect_src', None), ('jsx_not_sanitized', None)])

    if G.check_window_open:
        xss_rule_lists.append([('jsx_has_user_input', None), ('jsx_not_sanitized', None), ('jsx_has_callee_of_dom_op', None)])

    vul_type_map = {
        "xss": xss_rule_lists
    }

    rule_lists = vul_type_map[vul_type]
    success_paths = []

    for rule_list in rule_lists:
        vul_checking_res = jsx_do_vul_checking(G, rule_list, pathes)
        success_paths.extend(vul_checking_res)

    unique_pathes = set(tuple(path) for path in success_paths)
    success_paths = unique_pathes
    for index, path in enumerate(success_paths):
        loggers.main_logger.info(f'success_paths[{index}]: {path}')
    jsx_print_success_pathes(G, success_paths, color='green')

    return success_paths


def jsx_print_success_pathes(G, success_pathes, color=None):
    # for now, the success_pathes should be obj-edf edges
    used_pathes = success_pathes
    color_map = {
        'green': sty.fg.li_green,
        'red': sty.fg.li_red,
        'blue': sty.fg.li_blue,
        'yellow': sty.fg.li_yellow
    }
    if color in color_map:
        sty_color = color_map[color]
    else:
        sty_color = color

    if len(success_pathes):
        for p in success_pathes:
            loggers.main_logger.info(f"{sty_color}|Checker| success: {p}")

    path_id = 0

    ast_paths = [jsx_get_path_ast(G, path) for path in used_pathes]
    unique_ast_paths = set(tuple(path) for path in ast_paths)

    for index, path in enumerate(unique_ast_paths):
        if len(path) == 0:
            continue
        res_text_path = jsx_get_path_text(G, path, path[0])
        loggers.tmp_res_logger.info("|checker| success id${}$color:{}$: ".format(path_id, color))
        loggers.main_logger.info(path)
        loggers.main_logger.info(f"{sty_color}Attack Path ({index + 1}/{len(unique_ast_paths)}): ")
        print(f"{sty_color}Attack Path ({index + 1}/{len(unique_ast_paths)}): ")
        loggers.main_logger.info(f'{res_text_path} {sty.rs.all}')
        print(f'{res_text_path} {sty.rs.all}')

        path_id += 1
