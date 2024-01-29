from enum import Enum


class JSX_Edges:
    JSX_TO_AST = "JSX_TO_AST"
    JSX_DATA_FLOW = "JSX_DATA_FLOW"
    JSX_PARENT_OF = "JSX_PARENT_OF"
    JSX_COMPONENT_DEF = "JSX_COMPONENT_DEF"


class JSX_Nodes:
    JSX_Component = "JSX_Component"
    JSX_DOM = "JSX_DOM"


class JSX_Labels:
    JSX_REF = 'JSX_Ref'
    JSX_REF_CURRENT = 'JSX_Ref_Current'
    JSX_Props = "JSX_Props"


JSX_WHITE_LIST_PACKAGE = ['axios']
JSX_WHITE_LITE_IMPORT_SPECIFIER = ['memo', 'useState', 'useEffect', 'useRef', 'cloneElement', 'useParams']

JSX_Label_Key = 'jsx:label'

JSX_DOM_events = set(["onClick", "onChange", "onSubmit", "onFocus", "onBlur", "onMouseOver",
                      "onMouseOut", "onMouseDown", "onMouseUp", "onMouseMove", "onKeyDown",
                      "onKeyPress", "onKeyUp", "onTouchStart", "onTouchMove", "onTouchEnd",
                      "onDrag", "onDragOver", "onDragEnter", "onDragLeave", "onDragEnd", "onDrop"])

JSX_Custom_events = {
    ''
}


JSX_CLASS_MOUNTING_FUNCTION = [
    'constructor',
    'componentDidMount',
    'render',
]


JSX_CLASS_UPDATING_FUNCTION = [
    "getDerivedStateFromProps",
    "shouldComponentUpdate",
    "render",
    "getSnapshotBeforeUpdate",
    "componentDidUpdate"
]

JSX_CLASS_UNMOUNTING_FUNCTION = [
    "componentWillUnmount"
]


DOM_TAG_AND_ATTR_PAIRS = [
    ('a', 'href'),
    ('form', 'action'),
    ('iframe', 'src'),
    ('area', 'href'),
    ('button', 'formaction'),
    ('input', 'formaction'),
    ('frame', 'src'),
    ('script', 'src'),
    # do not directly use img src
    # ('img', 'src')
]
