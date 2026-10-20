from ast import (
    Assign,
    AsyncFunctionDef,
    Attribute,
    Call,
    ClassDef,
    Constant,
    FunctionDef,
    Import,
    ImportFrom,
    Name,
    Subscript,
    arg,
    unparse,
)

KIND = "tool"
DESCRIPTION = (
    "Show the structure of one file: every class, method and function with its line numbers and "
    "parameters, the module's imports and constants, and the marker lines where a secret, a "
    "request, a subprocess, a path, a deserializer, a template, a log call or a query appears. "
    "Call it before reading the file: it tells you which line ranges matter."
)
PARAMETERS = {
    "type": "object",
    "properties": {"path": {"type": "string", "description": "repository-relative file path"}},
    "required": ["path"],
}
EXAMPLE = {"path": "README.md"}

MARKERS = [
    "resolve_value", "to_dict", "from_dict", "Secret", "environ",
    "subprocess", "Popen", "os.system", "eval(", "exec(", "pickle", "yaml.load",
    "requests.", "httpx.", "urlopen", "urllib", "Path(", "open(", "os.path",
    ".format(", "Template", "SELECT", "INSERT", "UPDATE", "DELETE",
    "literal_eval", "import_module", "__import__", "jinja", "render", "logger.",
    "read_csv", "read_excel", "StringIO", "md5", "sha1", "verify=", "timeout",
    "shell=True", "escape", "startswith", "../", "join(", "replace(", "query",
]


def run(ctx, path):
    try:
        src = ctx.repo.read(path)
    except Exception as error:
        return "cannot read %s: %s" % (path, error)
    if not src.strip():
        return "%s: empty" % path
    lines = src.splitlines()
    out = ["%s (%d lines)" % (path, len(lines))]

    tree = ctx.repo.ast(path)
    if tree is not None:
        try:
            for node in tree.body:
                _describe(node, "", out)
        except Exception:
            pass
    else:
        out.append("(not parseable as Python; marker lines only)")

    hits = []
    for number, text in enumerate(lines, 1):
        low = text.lower()
        found = [m for m in MARKERS if m.lower() in low]
        if found and len(text.strip()) > 3:
            hits.append("%5d  %s  [%s]" % (number, text.strip()[:110], ",".join(found[:3])))
    if hits:
        out.append("marker lines:")
        out.extend(hits[:130])
        if len(hits) > 130:
            out.append("... %d more marker lines" % (len(hits) - 130))
    return "\n".join(out)[:14000]


def _describe(node, prefix, out):
    lineno = node.lineno
    if isinstance(node, ClassDef):
        end = node.end_lineno or lineno
        out.append("%s%-4d-%-4d class %s" % (prefix, lineno, end, node.name))
        for child in node.body:
            if isinstance(child, (FunctionDef, AsyncFunctionDef, ClassDef)):
                _describe(child, prefix + "  ", out)
        return
    if isinstance(node, (FunctionDef, AsyncFunctionDef)):
        end = node.end_lineno or lineno
        out.append("%s%-4d-%-4d def %s%s" % (prefix, lineno, end, node.name, _signature(node)))
        for child in node.body:
            if isinstance(child, (FunctionDef, AsyncFunctionDef, ClassDef)):
                _describe(child, prefix + "  ", out)
        return
    if isinstance(node, (Import, ImportFrom)):
        mod = getattr_ok(node, "module") or ""
        names = ", ".join(getattr_ok(a, "name") or "?" for a in node.names)
        out.append("%s%-4d import %s %s" % (prefix, lineno, mod, names[:110]))
        return
    if isinstance(node, Assign):
        targets = ", ".join(_name(t) for t in node.targets)
        out.append("%s%-4d %s = %s" % (prefix, lineno, targets, _name(node.value))[:160])


def getattr_ok(obj, name):
    try:
        if name == "module":
            return obj.module or ""
        return obj.name
    except Exception:
        return ""


def _signature(node):
    try:
        a = node.args
        parts = [_name(x) for x in list(a.posonlyargs) + list(a.args) + list(a.kwonlyargs)]
        if a.vararg is not None:
            parts.append("*" + a.vararg.arg)
        if a.kwarg is not None:
            parts.append("**" + a.kwarg.arg)
        return "(" + ", ".join(p for p in parts if p)[:170] + ")"
    except Exception:
        return "()"


def _name(node):
    try:
        if isinstance(node, Constant):
            return repr(node.value)[:60]
        if isinstance(node, Name):
            return node.id
        if isinstance(node, Attribute):
            return _name(node.value) + "." + node.attr
        if isinstance(node, Call):
            return _name(node.func) + "(...)"
        if isinstance(node, arg):
            return node.arg
        if isinstance(node, Subscript):
            return _name(node.value) + "[...]"
        if isinstance(node, (list, tuple)):
            return ", ".join(_name(x) for x in node)
        return unparse(node)[:60]
    except Exception:
        return "?"
