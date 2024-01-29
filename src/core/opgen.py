from src.core.jsx_constant import JSX_CLASS_MOUNTING_FUNCTION
from .graph import Graph
from .utils import *
from .helpers import *
from .timeout import timeout, TimeoutError
from func_timeout import func_timeout, FunctionTimedOut
from src.core.pop_funcs import pop_funcs
from ..plugins.manager import PluginManager
from ..plugins.internal.setup_env import setup_opg
from .checker import traceback, vul_checking
from .jsx_checker import jsx_traceback, jsx_vul_checking
from .multi_run_helper import validate_jsx_package, validate_package, get_entrance_files_of_package, get_entrance_files_of_jsx_package
from .logger import loggers
from .options import options
import os
import shutil
import sys
from tqdm import tqdm
import sty
import glob
import time
import subprocess
from collections import defaultdict, deque


class OPGen:
    """
    This is the major class for the whole opgen
    """

    def __init__(self):
        self.graph = Graph()
        self.options = options
        self.graph.package_name = options.input_file
        setup_graph_env(self.graph)

    def get_graph(self):
        """
        get the current graph
        Returns:
            Graph: the current OPG
        """
        return self.graph

    def check_vuls(self, vul_type, G):
        """
        check different type of vulnerabilities
        Args:
            vul_type: the type of vuls
            G: the graph
        Returns:
            the test result pathes of the module
        """
        vul_pathes = []

        if vul_type in ['os_command', 'path_traversal', 'code_exec', 'xss']:
            pathes = traceback(G, vul_type)
            vul_pathes = vul_checking(G, pathes[0], vul_type)

        return vul_pathes

    def jsx_check_vuls(self, vul_type, G):
        vul_pathes = []

        if vul_type in ['xss']:
            pathes = jsx_traceback(G, vul_type)
            vul_pathes = jsx_vul_checking(G, pathes[0], vul_type)
        else:
            raise ValueError("unsupported vulnerability type {}".format(vul_type))

        return vul_pathes

    def test_file(self, file_path, vul_type='os_command', G=None, timeout_s=None):
        """
        test a file as a js script
        Args:
            file_path (str): the path to the file
            vul_type (str) [os_command, prototype_pollution, xss]: the type of vul
            G (Graph): the graph we run top of
        Returns:
            list: the test result pathes of the module
        """
        # TODO: add timeout for testing file
        if G is None:
            G = self.graph
        try:
            parse_file(G, file_path)
        except Exception as exc:
            print(exc)
            print(sty.fg.li_red + sty.ef.inverse +
                  "[ERROR] AST parsing failed. Have you tried running the './install.sh' shell?\n"
                  + "This does not look like a bug. Please follow the README.md to install the tool\n"
                  + "And make sure the path to the package is correct."
                  + sty.rs.all)
        test_res = self._test_graph(G, vul_type=vul_type)
        return test_res

    def _test_graph(self, G: Graph, vul_type='os_command', second_start_node = None):
        """
        for a parsed AST graph, generate OPG and test vul
        Args:
            G (Graph): the Graph
            vul_type (str) [os_command, prototype_pollution, xss, ipt]: the type of vul
        Returns:
            list: the test result pathes of the module
        """
        from src.plugins.internal.handlers.functions import call_function
        setup_opg(G)
        G.export_node = True
        internal_plugins = PluginManager(G, init=True)
        entry_id = '0'

        start_time = time.time()
        generate_obj_graph(G, internal_plugins, entry_nodeid=entry_id)
        if options.service_entry and G.service_registry:
            for route in G.service_registry:
                target_func = G.service_registry[route]
                req_obj = G.add_obj_node(js_type='object', value = wildcard)
                G.set_node_attr(req_obj, ('tainted', True))
                req_obj_arg = NodeHandleResult(obj_nodes = [req_obj])
                call_function(G, func_objs=target_func, args=[req_obj_arg], mark_fake_args=False)
        if second_start_node:
            generate_obj_graph(G, internal_plugins, entry_nodeid=second_start_node)
        end_time = time.time()
        duration = end_time - start_time
        loggers.eval_logger.info(json.dumps({
            "entry_point": G.package_name,
            "duration_of_generating_graph": f"{duration:.2f}",
            "number_of_ast_nodes": G.num_of_ast_nodes
        }))
        print(f'Generating the graph took {duration:.2f} seconds')
        print(f'Number of AST Nodes: {G.num_of_ast_nodes}')

        if options.export:
            loggers.main_logger.info('start exporting graph to csv')
            G.export_to_CSV("./nodes.csv", "./rels.csv", light=False)
            loggers.main_logger.info('graph exported to csv')

        start_time = time.time()

        if vul_type is not None:
            check_res = self.jsx_check_vuls(vul_type, G)
            if len(check_res) != 0:
                self.graph.detection_res[vul_type].add(G.package_name)

        end_time = time.time()
        duration = end_time - start_time
        loggers.eval_logger.info(json.dumps({
            "duration_of_query": f"{duration:.2f}",
        }))
        print(f'Checking vulnerabilities took {duration:.2f} seconds')
        return check_res

    def test_module(self, module_path, vul_type='xss', G=None,
                    timeout_s=None, from_nodejs=False):
        """
        test a file as a module
        Args:
            module_path: the path to the module
            vul_type (str) [os_command, prototype_pollution, xss]: the type of vul
            G (Graph): the graph we run top of
        Returns:
            list: the test result pathes of the module
        """
        print("Testing {} {}".format(vul_type, module_path))
        if module_path is None:
            print(sty.fg.li_red + sty.ef.inverse +
                  "[ERROR] {} not found".format(module_path)
                  + sty.rs.all)
            loggers.error_logger.error("[ERROR] {} not found".format(module_path))
            return []

        if G is None:
            G = self.graph

        test_res = []
        # only consider the finished packages
        output_code_coverage = True
        module_timedout = True
        single_mode_tried = False

        while (module_timedout):
            module_timedout = False
            G = self.get_new_graph(package_name=module_path)

            jsx_start_id = 0
            if options.service_entry:
                service_call_template = "var main_func=require('{}');".format(options.service_entry)
                parse_string(G, service_call_template)
                jsx_start_id = G.cur_id+ 1
            if options.is_nextjs_application:
                options.is_jsx_application = False
            if options.is_jsx_application:
                parse_file(G, module_path, start_node_id=jsx_start_id)
            else:

                if options.nodejs:
                    js_call_templete = "var main_func=require('{}');".format(module_path)
                else:
                    js_call_templete = f"import * as entry from '{module_path}'"
                try:
                    parse_string(G, js_call_templete, start_node_id=jsx_start_id)
                except:
                    return []

            if timeout_s is not None:
                try:
                    test_res = func_timeout(timeout_s, self._test_graph, args=(G, vul_type, jsx_start_id))
                except FunctionTimedOut:
                    error_msg = "{} timedout after {} seconds".format(module_path, timeout_s)
                    output_code_coverage = False
                    loggers.error_logger.error(error_msg)
                    print(f'number of ast node: {G.num_of_ast_nodes}')
                    raise
                except Exception as e:
                    loggers.error_logger.error(f"An error occurred: {e}")
                    raise
            else:
                test_res = self._test_graph(G, vul_type=vul_type)

            # if module_timedout:
            #     if single_mode_tried:
            #         print("timed out, trying to reduce the max_rep")
            #         options.max_rep = int(options.max_rep / 2)
            #         print("max_rep has been reduced to {}".format(options.max_rep))
            #         if options.max_rep == 0:
            #             break
            #     else:
            #         print("timed out, trying to use single branch mode")
            #         options.single_branch = True
            #         single_mode_tried = True

        if module_timedout:
            error_msg = "{} timedout after {} seconds".format(module_path, timeout_s)
            loggers.res_logger.error(error_msg)

        if output_code_coverage:
            covered_stat = len(self.graph.get_covered_statements())
            total_stat = self.graph.get_total_num_statements()

            if total_stat != 0:
                # should not happen, just in case it is a totally blank package
                loggers.stat_logger.info(f"CC:{covered_stat / total_stat}")

        return test_res

    def test_nodejs_package(self, package_path, vul_type='os_command', G=None,
                            timeout_s=None):
        """
        test a nodejs package
        Args:
            package_path (str): the path to the package
        Returns:
            the result state: 1 for found, 0 for not found, -1 for error
        """
        if not validate_package(package_path):
            print(sty.fg.li_red + sty.ef.inverse +
                  "[ERROR] {} not found".format(package_path)
                  + sty.rs.all)
            return -1
        if G is None:
            G = self.graph

        entrance_files = get_entrance_files_of_package(package_path)

        loggers.detail_logger.info(f"{G.package_name} started")
        for entrance_file in entrance_files:
            if G.finished:
                break
            test_res = self.test_module(entrance_file, vul_type, G, timeout_s=timeout_s, from_nodejs=True)
            if len(test_res) != 0:
                break

    def test_jsx_package(self, package_path, vul_type='xss', G=None, timeout_s=None, is_jsx_application=False):
        """
        test a jsx package
        Args:
            package_path (str): the path to the package or the input file.
        Returns:
            the result state: 1 for found, 0 for not found, -1 for error
        """
        if os.path.isdir(package_path) and not validate_jsx_package(package_path):
            print(sty.fg.li_red + sty.ef.inverse + "[ERROR] {} is not a valid package".format(package_path) + sty.rs.all)
            return -1
        if G is None:
            G = self.graph
        
        if os.path.isfile(package_path):
            entrance_files = [package_path]
        else:
            entrance_files = get_entrance_files_of_jsx_package(package_path, options=options)
            entrance_files.sort()
        loggers.main_logger.info(f"Package started: {G.package_name}")
        loggers.main_logger.info(f"JSX entry points: {entrance_files}")
        if not entrance_files:
            raise ValueError(f'can not find entry point for {package_path}')
        for entrance_file in entrance_files:
            if G.finished:
                break
            loggers.main_logger.info(f'testing entry point: {entrance_file}')
            test_res = self.test_module(entrance_file, vul_type, G, timeout_s=timeout_s, from_nodejs=True)
            if len(test_res) != 0:
                break

            
    def get_new_graph(self, package_name=None):
        """
        set up a new graph
        """
        self.graph = Graph()
        if not package_name:
            self.graph.package_name = options.input_file
        else:
            self.graph.package_name = package_name
        setup_graph_env(self.graph)
        return self.graph

    def output_args(self):
        loggers.main_logger.info("All args:")
        keys = [i for i in options.instance.__dict__.keys() if i[:1] != '_']
        for key in keys:
            loggers.main_logger.info("{}: {}".format(key,
                                                     options.instance.__dict__[key]))

    def run(self):
        self.output_args()
        if not os.path.exists(options.run_env):
            os.mkdir(options.run_env)

        timeout_s = options.timeout
        if options.install:
            # we have to provide the list if we want to install
            package_list = []
            with open(options.list, 'r') as fp:
                for line in fp.readlines():
                    package_path = line.strip()
                    package_list.append(package_path)
            install_list_of_packages(package_list)
            return

        if options.run_test:
            # simple solution, should be updated later
            from src.core.test import run_tests
            run_tests()
            return

        if options.parallel is not None:
            prepare_split_list()
            num_thread = int(options.parallel)
            tmp_args = sys.argv[:]
            parallel_idx = tmp_args.index("--parallel")
            tmp_args[parallel_idx] = tmp_args[parallel_idx + 1] = ''
            try:
                list_idx = tmp_args.index("-l")
            except:
                list_idx = tmp_args.index("--list")
            for i in range(num_thread):
                cur_list_path = os.path.join(options.run_env, "tmp_split_list", str(i))
                tmp_args[list_idx + 1] = cur_list_path
                cur_cmd = ' '.join(tmp_args)
                os.system(f"screen -S runscreen_{i} -dm {cur_cmd}")
            return

        if options.babel:
            babel_convert()
        if options.list is not None:
            package_list = []
            with open(options.list, 'r') as fp:
                for line in fp.readlines():
                    package_path = line.strip()
                    package_path = os.path.expanduser(package_path)
                    package_list.append(package_path)

            for package_path in package_list:
                # init a new graph
                self.get_new_graph(package_name=package_path)
                # self.test_module(package_path, options.vul_type, self.graph, timeout_s=timeout_s)
                self.test_nodejs_package(package_path,
                                         options.vul_type, self.graph, timeout_s=timeout_s)

                if len(self.graph.detection_res[options.vul_type]) != 0:
                    loggers.succ_logger.info("{} is detected in {}".format(
                        options.vul_type,
                        package_path))
                else:
                    loggers.res_logger.info("Not detected in {}".format(
                        package_path))

        else:
            if options.module:
                self.test_module(options.input_file, options.vul_type, self.graph, timeout_s=timeout_s)
            elif options.jsx_package:
                self.test_jsx_package(options.input_file, options.vul_type, G=self.graph, timeout_s=timeout_s, is_jsx_application=options.is_jsx_application)
            elif options.nodejs:
                self.test_nodejs_package(options.input_file,
                                         options.vul_type, G=self.graph, timeout_s=timeout_s)
            else:
                # analyze from JS source code files
                self.test_file(options.input_file, options.vul_type, self.graph, timeout_s=timeout_s)

            if len(self.graph.detection_res[options.vul_type]) != 0:
                print(sty.fg.li_green + sty.ef.inverse +
                      f'{options.vul_type} detected at {options.input_file}'
                      + sty.rs.all)
                loggers.succ_logger.info("{} is detected in {}".format(
                    options.vul_type,
                    options.input_file))
            else:
                loggers.res_logger.info("Not detected in {}".format(
                    options.input_file))

        if len(self.graph.detection_res[options.vul_type]) == 0:
            print(sty.fg.li_red + sty.ef.inverse +
                  f'{options.vul_type} not detected. Have you tried the "-ma" argument?\n' +
                  "If it's a Node.js package, you can also try the '--nodejs -a' argument."
                  + sty.rs.all)
        print("Graph size: {}, GC removed {} nodes".format(self.graph.get_graph_size(), self.graph.num_removed))
        if options.export is None:
            print(f"Cleaning up tmp dirs: {options.run_env}")
            shutil.rmtree(options.run_env)
        # export to csv
        if options.export is not None:
            if options.export == 'light':
                self.graph.export_to_CSV("./exports/nodes.csv", "./exports/rels.csv", light=True)
            else:
                self.graph.export_to_CSV("./exports/nodes.csv", "./exports/rels.csv", light=False)


def start_from_func(G: Graph, module_path, vul_type='proto_pollution'):
    """
    start from a special function
    """
    # start from a special function
    # pre-run the file, set the file stack limit to 2
    from src.plugins.internal.handlers.functions import call_function, run_exported_functions, ast_call_function
    # pretend another file is requiring this module
    js_call_templete = "var main_func=require('{}');".format(module_path)
    js_call_templete = module_path
    parse_string(G, js_call_templete)
    setup_opg(G)
    entry_nodeid = '0'
    internal_plugins = PluginManager(G, init=True)
    NodeHandleResult.print_callback = print_handle_result

    entry_nodeid = str(entry_nodeid)
    loggers.main_logger.info(sty.fg.green + "GENERATE COMPONENT GRAPH" + sty.rs.all + ": " + entry_nodeid)
    obj_nodes = G.get_nodes_by_type("AST_FUNC_DECL")
    for node in obj_nodes:
        register_func(G, node[0])

    user_max_file_stack = options.max_file_stack
    user_run_all = options.run_all
    print("Pre-running file")
    # options.max_file_stack = 1
    options.run_all = False
    options.no_exports = True

    # this process should not take very long
    # let's set a limit for this process
    try:
        func_timeout(options.pre_timeout, internal_plugins.dispatch_node, args=(entry_nodeid, None))
    except FunctionTimedOut:
        print("Pre-run file timedout")

    print("Pre run finished")

    options.max_file_stack = user_max_file_stack
    options.run_all = user_run_all
    options.no_exports = False
    G.call_stack = []
    G.file_stack = []

    obj_nodes = G.get_nodes_by_type("AST_FUNC_DECL")
    file_nodes = G.get_nodes_by_type("AST_TOPLEVEL")
    closure_nodes = G.get_nodes_by_type("AST_CLOSURE")
    if options.timeout:
        function_timeout_s = options.timeout / 4
    else:
        function_timeout_s = 30

    if options.entrance_func is not None:
        target_list = [options.entrance_func]
    else:
        target_list = pop_funcs

    print("Entrance function list: {}".format(target_list))
    detection_res = None
    check_res = []
    for func in target_list:
        if G.finished:
            break
        for file_node in file_nodes:
            if file_node[1].get('name') == options.input_file:
                scope_edges = G.get_in_edges(file_node[0], edge_type="SCOPE_TO_AST")
                for scope_edge in scope_edges:
                    scope_node = scope_edge[0]
                    var_obj_nodes = G.get_objs_by_name(func, scope=scope_node)
                    if len(var_obj_nodes) != 0:
                        print("Running {} by under scope".format(func))
                        try:
                            func_timeout(function_timeout_s, run_exported_functions, args=(G, var_obj_nodes, None))
                            if vul_type == 'os_command' or vul_type == 'path_traversal':
                                pathes = traceback(G, vul_type)
                                check_res = vul_checking(G, pathes[0], vul_type)
                            if len(check_res) != 0:
                                G.detection_res[vul_type].add(G.package_name)
                        except FunctionTimedOut:
                            pass

        # if not found, try another way
        if len(G.detection_res[vul_type]) != 0:
            continue

        all_name_nodes = G.get_nodes_by_type("NAMENODE")
        for name_node in all_name_nodes:
            if name_node[1].get("name") == func:
                cur_obj_nodes = G.get_objs_by_name_node(name_node[0])
                if len(cur_obj_nodes) != 0:
                    print("Running {} by name node".format(func))
                    try:
                        func_timeout(function_timeout_s, run_exported_functions, args=(G, cur_obj_nodes, None))
                        if vul_type == 'os_command' or vul_type == 'path_traversal':
                            pathes = traceback(G, vul_type)
                            check_res = vul_checking(G, pathes[0], vul_type)

                        if len(check_res) != 0:
                            G.detection_res[vul_type].add(G.package_name)
                    except FunctionTimedOut:
                        pass
                    # call_function(G, cur_obj_nodes, mark_fake_args=True)
    # we need to check the vuls

    print(G.detection_res)
    return G.detection_res[vul_type]


def generate_obj_graph(G: Graph, internal_plugins, entry_nodeid='0', OPGen=None):
    """
    generate the component graph of a program
    Args:
        G (Graph): the graph to generate
        internal_plugins（PluginManager): the plugin obj
        entry_nodeid (str) 0: the entry node id,
            by default 0
    """
    from src.plugins.internal.handlers.functions import call_function, run_exported_functions, ast_call_function
    from src.plugins.internal.handlers.jsx_element import update_jsx_comp
    NodeHandleResult.print_callback = print_handle_result

    entry_nodeid = str(entry_nodeid)
    loggers.main_logger.info(sty.fg.green + "GENERATE COMPONENT GRAPH" + sty.rs.all + ": " + entry_nodeid)
    obj_nodes = G.get_nodes_by_type("AST_FUNC_DECL")
    for node in obj_nodes:
        register_func(G, node[0])
    internal_plugins.dispatch_node(entry_nodeid)

    loggers.main_logger.info(f'Graph generation complete. Size: {G.get_graph_size()}')

    if not options.is_jsx_application:
        file_path = G.package_name
        toplevel_nodes = G.get_nodes_by_type_and_flag('AST_TOPLEVEL', 'TOPLEVEL_FILE')
        module_exports_objs = []
        found = False
        for node in toplevel_nodes:
            if G.get_node_attr(node).get('name') == file_path:
                found = True
                # if a file has been required, skip the run and return
                # the saved module.exports
                node_attr = G.get_node_attr(node)
                saved_module_exports = G.get_node_attr(node).get('module_exports')
                if saved_module_exports != None:
                    module_exports_objs = saved_module_exports
                    break
                else:
                    raise ValueError(f"cannot find any module exports, node: {node}")
        if not found:
            print(f"cannot find file matched {file_path}")
        
        if options.entrance_func is not None:
            entrance_func_objs = set()
            for obj in module_exports_objs:
                name_nodes = G.get_name_nodes_to_obj(obj)
                for name_node in name_nodes:
                    name_node_attr = G.get_node_attr(name_node)
                    if name_node_attr.get('name') == options.entrance_func:
                        entrance_func_objs.add(obj)
            run_exported_functions(G, module_exports_objs=list(entrance_func_objs), extra=None, mark_fake_args = True)
        else:
            run_exported_functions(G, module_exports_objs=module_exports_objs, extra=None, mark_fake_args = True)
            if module_exports_objs:
                prototypes = G.get_prop_obj_nodes(module_exports_objs[0], 'prototype')
                if prototypes:
                    for p in prototypes:
                        mouting_funcs = []
                        for func_name in JSX_CLASS_MOUNTING_FUNCTION:
                            mouting_funcs += G.get_prop_obj_nodes(parent_obj=p, prop_name=func_name)                       
                        this_obj = G.add_obj_node()
                        props_obj = G.add_obj_node(value=wildcard)
                        G.set_node_attr(props_obj, ('tainted', True))
                        state_obj = G.add_obj_node()
                        G.add_obj_as_prop(prop_name='props', js_type='object', parent_obj=this_obj, tobe_added_obj=props_obj)
                        G.add_obj_as_prop(prop_name='state', js_type='object', parent_obj=this_obj, tobe_added_obj=state_obj)

                        def class_set_state(G: Graph, caller_ast, extra, _, *args):
                            class_this_state_name_node = G.get_prop_name_node('state', parent_obj=this_obj)
                            if not class_this_state_name_node:
                                return NodeHandleResult()
                            for new_state_obj in args[0].obj_nodes:
                                G.add_obj_to_name_node(name_node=class_this_state_name_node, tobe_added_obj=new_state_obj)
                            return NodeHandleResult()
                        G.add_blank_func_as_prop(func_name='setState', parent_obj=this_obj, python_func=class_set_state)
                        call_function(G, mouting_funcs, args=[], is_new=False, this=NodeHandleResult(obj_nodes=[this_obj]), mark_fake_args=True)

    jsx_snapshot = G.get_jsx_comp_tree_snapshot()
    while True:
        if G.task_queue:
            func1 = G.task_queue.popleft()
            func1(func1, G)
        while True:  # always check the micro task queue
            if G.microtask_queue:
                func2 = G.microtask_queue.popleft()
                func2(func2, G)
            else:
                break
        if not G.task_queue:
            break
    while True:
        if G.dom_events_queue:
            func1 = G.dom_events_queue.popleft()
            func1()
        if not G.dom_events_queue:
            break

    start_time = time.time()
    jsx_snapshot_after_events = G.get_jsx_comp_tree_snapshot()
    end_time = time.time()
    duration = end_time - start_time
    loggers.eval_logger.info(json.dumps({
        "duration_of_snapshot": f"{duration:.6f}",
        "jsx_nodes": len(G.get_all_jsx_component_nodes())
    }))
    start_time = time.time()
    diff_comps = G.diff_snapshots(jsx_snapshot, jsx_snapshot_after_events)
    for jsx_comp in diff_comps:
        G.comp_update_queue.append(jsx_comp)
    end_time = time.time()
    duration = end_time - start_time
    loggers.eval_logger.info(json.dumps({
        "duration_of_diff": f"{duration:.6f}",
        "jsx_nodes": len(G.get_all_jsx_component_nodes())
    }))
    start_time = time.time()
    comp_update_list = list(set(G.comp_update_queue))
    comp_update_list.sort()
    comp_update_list.reverse()
    loggers.eval_logger.info(json.dumps({
        "updating_times": len(comp_update_list)
    }))
    G.updating_phase = True
    while True:
        if comp_update_list:
            jsx_comp = comp_update_list.pop(0)
            update_jsx_comp(G, jsx_comp)
        if not comp_update_list:
            break
    G.updating_phase = False
    end_time = time.time()
    duration = end_time - start_time
    loggers.eval_logger.info(json.dumps({
        "duration_of_updating": f"{duration:.6f}"
    }))

    if G.cleanup_funcs:
        call_function(G, func_objs=G.cleanup_funcs, args=[], mark_fake_args=False)

def install_list_of_packages(package_list):
    """
    install a list of packages into environment/packages/
    """
    from tools.package_downloader import download_package
    package_root_path = os.path.join(options.run_env, "packages")
    package_root_path = os.path.abspath(package_root_path)
    if not os.path.exists(package_root_path):
        os.mkdir(package_root_path)
    print("Installing packages")
    version_number = None
    for package in tqdm(package_list):
        if '@' in package and package[0] != '@':
            version_number = package.split('@')[1]
            package = package.split('@')[0]

        download_package(package, version_number, target_path=package_root_path)


def setup_graph_env(G: Graph):
    """
    setup the graph environment based on the user input

    Args:
        G (Graph): the Graph to setup
        options (options): the user input options
    """
    from src.plugins.manager_instance import internal_manager
    internal_manager.update_graph(G)

    if options.print:
        G.print = True
    G.run_all = options.run_all or options.list
    if G.run_all is None:
        G.run_all = False
    # options.module or options.nodejs or options.list
    G.function_time_limit = options.function_timeout

    G.exit_when_found = options.exit
    G.single_branch = options.single_branch
    G.vul_type = options.vul_type
    G.func_entry_point = options.entry_func
    G.no_file_based = options.no_file_based
    G.check_proto_pollution = (options.prototype_pollution or
                               options.vul_type == 'proto_pollution')
    G.check_ipt = (options.vul_type == 'ipt')

    # let's set exported func timeout to be 0.5 timeout
    # make sure we run at least 2 exported funcs
    # if options.timeout:
    #    options.exported_func_timeout = int(options.timeout * 0.5)

    G.call_limit = options.call_limit
    G.detection_res[options.vul_type] = set()
    if hasattr(options, 'mark_tainted'):
        G.mark_tainted = options.mark_tainted


def babel_convert():
    """
    use babel to convert the input files to ES5
    for now, we use system commands
    """
    try:
        shutil.rmtree(options.run_env)
    except:
        # sames the run_env does not exsit
        pass
    babel_location = "../node_modules/@babel/cli/bin/babel.js"
    babel_cp_dir = os.path.join(options.run_env, 'babel_cp')
    babel_env_dir = os.path.join(options.run_env, 'babel_env')
    babel_config_dir = "../.babelrc"
    if os.path.isdir(options.input_file):
        relative_path = os.path.relpath(options.input_file, options.babel)
        options.input_file = os.path.abspath(os.path.join(babel_env_dir, relative_path))
    else:
        if options.input_file.endswith('.tsx'):
            options.input_file = options.input_file.replace('.tsx', '.js')
        elif options.input_file.endswith('.ts'):
            options.input_file = options.input_file.replace('.ts', '.js')
        filename = os.path.basename(options.input_file)
        options.input_file = os.path.abspath(os.path.join(babel_env_dir, filename))

    os.system(f"mkdir {options.run_env} {babel_cp_dir} {babel_env_dir}")

    # copy input to babel_cp_dir
    os.makedirs(babel_cp_dir, exist_ok=True)
    if os.path.isdir(options.babel):
        for item in os.listdir(options.babel):
            source_item = os.path.join(options.babel, item)
            dest_item = os.path.join(babel_cp_dir, item)
            if os.path.isdir(source_item):
                shutil.copytree(source_item, dest_item, dirs_exist_ok=True)
            else:
                shutil.copy2(source_item, dest_item)
    elif os.path.isfile(options.babel):
        shutil.copy2(options.babel, babel_cp_dir)

    for root, dirs, files in os.walk(babel_cp_dir):
        for file in files:
            if not file.endswith(('.ts', '.tsx', '.d.ts')):
                src = os.path.join(root, file)
                dst = os.path.join(babel_env_dir, os.path.relpath(src, babel_cp_dir))
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy(src, dst)
        # explicitly copy empty dirs
        for dir in dirs:
            dst = os.path.join(babel_env_dir, os.path.relpath(os.path.join(root, dir), babel_cp_dir))
            os.makedirs(dst, exist_ok=True)

    # Handle the TS files and put result into cur dir
    babel_cmd = f"{babel_location} {babel_cp_dir} --out-dir {babel_env_dir} --extensions .ts,.tsx --config-file {babel_config_dir}"
    exit_status = os.system(babel_cmd)

    if exit_status == 0:
        print("The babel command executed successfully.")
    else:
        print(f"The babel command failed with status code: {exit_status}")
        # raise ValueError(f"The babel command failed with status code: {exit_status}")

    print("New entry point {}".format(options.input_file))


def prepare_split_list():
    """
    split the list into multiple sub lists
    """
    # if the parallel is true, we will start a list of screens
    # each of the screen will include another run
    num_thread = int(options.parallel)
    # make a tmp dir to store the
    tmp_list_dir = "tmp_split_list"
    os.system("mkdir {}".format(os.path.join(options.run_env, tmp_list_dir)))
    package_list = None
    with open(options.list, 'r') as fp:
        package_list = fp.readlines()

    num_packages = len(package_list)
    chunk_size = math.floor(num_packages / num_thread)
    sub_package_lists = [[] for i in range(num_thread)]
    file_pointer = 0
    for package in package_list:
        sub_package_lists[file_pointer % num_thread].append(package)
        file_pointer += 1

    cnt = 0
    for sub_packages in sub_package_lists:
        with open(os.path.join(options.run_env, tmp_list_dir, str(cnt)), 'w') as fp:
            fp.writelines(sub_packages)
        cnt += 1
