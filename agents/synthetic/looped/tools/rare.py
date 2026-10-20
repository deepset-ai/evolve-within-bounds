KIND = "tool"
import re

DESCRIPTION = (
    "'Odd one out' census of the repository's sink sites. Section A: lines whose shape is unique "
    "inside a family of several similar calls, shown next to the shape the rest of the family "
    "shares. Section B: the same for small sink families (requests, secrets, subprocess, paths, "
    "deserializers, logs, queries). Section C: dangerous APIs (eval, exec, shell, pickle, "
    "yaml.load, import of a computed name, urlopen, md5) that the project uses in exactly one "
    "place. In a project of ordinary code with one defect, the edited statement is usually one of "
    "these lines. Read each one and decide whether the difference is a missing control - an "
    "argument the family always passes, a helper it calls, a wrapper it applies, a binding instead "
    "of concatenation - or only a differently-worded but equivalent line."
)
PARAMETERS = {
    "type": "object",
    "properties": {
        "pattern": {"type": "string", "description": "optional regular expression restricting the census"},
        "min": {"type": "integer", "description": "smallest family size for section A (default 4)"},
    },
    "required": [],
}
EXAMPLE = {}

CODE_EXT = (".py", ".sql", ".yaml", ".yml", ".toml", ".sh", ".jinja2", ".j2", ".rb", ".java", ".ts", ".js")
SKIP_PARTS = ("test", "docs/", "example", ".git/", "node_modules", "migrations", "license")

SINK = re.compile(
    r"request|httpx|urlopen|urllib|urlretrieve|aiohttp|client|session|post|get|put|delete|"
    r"subprocess|popen|system|exec|eval|pickle|yaml|marshal|shelve|dill|joblib|loads|load|"
    r"secret|token|api_key|apikey|password|credential|environ|getenv|auth|"
    r"path|open|glob|remove|rename|rmtree|copy|write|temp|mkdir|unlink|"
    r"select|insert|update|delete|query|execute|format|template|render|join|replace|"
    r"log|print|warn|error|info|debug|"
    r"read_csv|read_excel|read_parquet|to_dict|from_dict|deserialize|serialize|"
    r"escape|quote|sanitiz|redact|valid|check|allow|verify|hash|md5|sha|timeout|send|run|"
    r"import|getattr|setattr|getattr|html|xml|command|args",
    re.IGNORECASE,
)

DANGEROUS = re.compile(
    r"^(eval|exec|execfile|compile|system|popen|spawn\w*|run|check_output|check_call|call|"
    r"loads|load|exec_module|import_module|__import__|urlopen|urlretrieve|md5|sha1|setattr|"
    r"getattr|eval_|literal_eval)$|^(os|subprocess|pickle|cPickle|dill|joblib|marshal|shelve|"
    r"yaml|ast|builtins|importlib|requests|httpx|urllib\.request|sh|pty|pty\.spawn)$",
    re.IGNORECASE,
)

CALL = re.compile(r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(")


def _shape(text):
    s = text.strip()
    s = re.sub(r"\"[^\"]*\"", "S", s)
    s = re.sub(r"'[^']*'", "S", s)
    s = re.sub(r"\b\d[\d_.x]*\b", "N", s)
    s = re.sub(r"\s+", " ", s)
    return s[:150]


def _wanted(path):
    low = path.lower()
    if not low.endswith(CODE_EXT):
        return False
    if low.startswith("license") or "/license" in low:
        return False
    parts = low.split("/")
    if any(p in ("tests", "test", "docs", "doc", "node_modules", "migrations") for p in parts[:-1]):
        return False
    base = parts[-1]
    return not (base.startswith("test_") or base.endswith("_test.py") or base in (".gitignore", "license"))


def build(ctx):
    if "census" in ctx.state:
        return ctx.state["census"]
    census = {}
    for path in ctx.repo.files:
        if not _wanted(path):
            continue
        try:
            lines = ctx.repo.lines(path)
        except Exception:
            continue
        for number, text in enumerate(lines, 1):
            stripped = text.strip()
            if len(stripped) < 12 or stripped.startswith(("#", "//", "*", ":", ">>>", '"', "'")):
                continue
            if re.match(r"^(async\s+)?(def|class)\b", stripped) or stripped.startswith("return "):
                continue
            match = CALL.search(stripped)
            if match is None:
                continue
            name = match.group(1)
            if name in ("if", "while", "assert", "for", "lambda", "not", "elif", "with", "yield"):
                continue
            low = name.lower()
            if SINK.search(low) is None:
                continue
            if low.endswith(".get") and SINK.search(stripped.lower()) is None:
                continue
            census.setdefault(low, {}).setdefault(_shape(stripped), []).append((path, number, stripped))
    ctx.state["census"] = census
    return census


def run(ctx, pattern=None, min=4):
    try:
        rx = re.compile(pattern) if pattern else None
    except Exception as error:
        return "bad pattern: %s" % error
    try:
        floor = max(3, int(min))
    except Exception:
        floor = 4

    census = build(ctx)

    def keep(text):
        return rx is None or rx.search(text) is not None

    section_a = []
    section_b = []
    section_c = []
    for name, variants in census.items():
        shapes = {s: m for s, m in variants.items() if any(keep(t) for _p, _n, t in m)}
        if not shapes:
            continue
        total = sum(len(m) for m in shapes.values())
        unique = [(s, m[0]) for s, m in shapes.items() if len(m) == 1]
        repeated = sorted(((s, len(m)) for s, m in shapes.items() if len(m) > 1), key=lambda kv: -kv[1])

        if len(shapes) > 1 and total >= floor and unique and repeated:
            block = ["== %s: %d calls, %d shapes" % (name, total, len(shapes))]
            for _s, (path, line, text) in unique[:6]:
                block.append("   UNIQUE %s:%d  %s" % (path, line, text[:150]))
            for shape, count in repeated[:2]:
                block.append("   %dx the rest: %s" % (count, shape[:140]))
            section_a.append((total, "\n".join(block)))
        elif len(shapes) > 1 and total >= 2 and unique:
            block = ["== %s: %d calls, %d shapes" % (name, total, len(shapes))]
            for shape, members in sorted(shapes.items(), key=lambda kv: (len(kv[1]), kv[0]))[:5]:
                tag = "UNIQUE" if len(members) == 1 else "%dx" % len(members)
                block.append("   [%s] %s" % (tag, shape[:140]))
                for path, line, _t in members[:3]:
                    block.append("          %s:%d" % (path, line))
            section_b.append((total, "\n".join(block)))
        elif total == 1 and DANGEROUS.search(name) is not None:
            path, line, text = list(shapes.values())[0][0]
            section_c.append("%s:%d  %s  [%s is used nowhere else]" % (path, line, text[:150], name))

    section_a.sort(key=lambda kv: -kv[0])
    section_b.sort(key=lambda kv: -kv[0])
    out = []
    if section_a:
        out.append("A. lines written differently from a family that repeats elsewhere:")
        out.extend(b for _t, b in section_a[:22])
    if section_b:
        out.append("")
        out.append("B. sink families whose calls are not all written the same:")
        out.extend(b for _t, b in section_b[:28])
    if section_c:
        out.append("")
        out.append("C. dangerous API used in exactly one place:")
        out.extend(section_c[:20])
    if not out:
        return "no sink family shows an odd-one-out line" + (" for this pattern" if pattern else "")
    text = "\n".join(out)
    if len(text) > 13000:
        text = text[:13000] + "\n... truncated: narrow with pattern="
    return text
