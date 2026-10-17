KIND = "step"
import re

# Three deterministic control-coverage detectors. Each compares the project's own statements with
# each other, so a repository that applies the control everywhere reports nothing (which is what
# keeps a fixed twin clean). No model calls.
#
# D1 pinned target   - the file defines its API endpoint as a module constant, but a request is
#                      aimed at a value the caller of run() or the pipeline configuration controls.
# D2 environment write - a value taken from the caller's arguments is written into the process
#                      environment, where the rest of the project only reads environment variables.
# D3 guard coverage  - a helper of this project whose job is to contain, encode, redact, validate or
#                      authorize a value is applied at some statements of that kind and omitted at
#                      another statement of the same kind.
#
# The locations found are stored in ctx.state["coverage"] so a later step can protect them.

GUARD_WORDS = (
    "redact", "mask", "scrub", "escape", "quote", "encod", "sanitiz", "clean", "strip",
    "contain", "normaliz", "canonical", "validate", "verify", "check", "allowed",
    "restrict", "safe", "coerce", "guard", "confine", "within",
)

SINKS = [
    ("request", r"(?:urlopen|urlretrieve|urllib\.request|requests?\.[a-z]+|httpx\.[a-z]+|aiohttp|"
                r"session\.[a-z]+\(|\.request\(|request_with_retry|Request\()"),
    ("log", r"(?:logger|log|logging)\.(?:info|warning|warn|error|exception|critical|debug)\(|print\("),
    ("shell", r"(?:subprocess\.(?:run|call|Popen|check_output|check_call|spawn\w*)|os\.system|os\.popen)"),
    ("path", r"(?:Path\(|\bopen\(|io\.open|os\.path\.(?:join|abspath|realpath|normpath)|shutil\.\w+|"
             r"os\.(?:remove|rename|mkdir|listdir|walk)|tempfile\.\w+|\.resolve\(\))"),
    ("sql", r"(?:(?:execute(?:_many)?|\.(?:query|sql))\(|SELECT |INSERT |UPDATE |DELETE )"),
    ("html", r"(?:f?[\"'][^\"']*<(?:a|li|p|div|span|img|script|td|tr|h[1-6])\b|"
             r"Template\(|from_string|render_template_string|\.render\()"),
    ("env", r"os\.environ(?:\[|\.setdefault)|os\.environ\.update|setenv\("),
    ("load", r"(?:pickle\.loads?|yaml\.load|marshal\.loads?|pd\.read_\w+|import_module|__import__|"
             r"(?<![\w.])eval\(|(?<![\w.])exec\()"),
    ("serialize", r"(?:default_to_dict\(|model_dump\(|asdict\(|json\.dumps\()"),
    ("urlbuild", r"(?:urljoin|urlencode|urlparse|urlunparse|f[\"']https?://)"),
]
SINK_KIND = {name: re.compile(rx) for name, rx in SINKS}

NAME_KIND = [
    (r"redact|mask|scrub|sanitiz|clean", {"log"}),
    (r"escape|quote", {"html", "urlbuild", "path", "sql"}),
    (r"url|origin|host|endpoint|redirect|target", {"request", "urlbuild"}),
    (r"path|file|contain|confine|within|normaliz|canonical|resolve", {"path"}),
    (r"sql|query|table|ident", {"sql"}),
    (r"shell|command|argv", {"shell"}),
    (r"env|environ", {"env"}),
    (r"size|limit|bound", set()),
]
NAME_RX = re.compile(r"\b\w*(?:%s)\w*\b" % "|".join(GUARD_WORDS), re.IGNORECASE)

CONST_URL = re.compile(r"^([A-Z][A-Z0-9_]*(?:URL|ENDPOINT|HOST|URI)[A-Z0-9_]*)\s*=\s*[\"']"
                       r"(https?://[^\"']+)[\"']")
ENV_WRITE = re.compile(r"os\.environ\s*\[\s*[\"']?[\w.]+[\"']?\s*\]\s*=\s*(.+)")
TARGET_ARG = re.compile(r"(?:url|uri|endpoint|base_url|target)\s*=\s*([^,)]+)|"
                        r"(?:urlopen|Request|get|post|put|delete|request_with_retry)\s*\(\s*([^,)]+)")

CODE_EXT = (".py", ".sql", ".yaml", ".yml", ".toml", ".sh", ".jinja2", ".j2")
SKIP_DIRS = ("tests", "test", "docs", "doc", "node_modules", "migrations", "examples", "example")
NEAR = 4
MAX_REPORTS = 6


def _wanted(path):
    low = path.lower()
    if not low.endswith(CODE_EXT):
        return False
    parts = low.split("/")
    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False
    base = parts[-1]
    return not (base.startswith("test_") or base.endswith("_test.py") or "license" in base)


def _classify(text):
    return [name for name, rx in SINK_KIND.items() if rx.search(text)]


def _shape(text):
    s = text.strip()
    s = re.sub(r"\"[^\"]*\"", "S", s)
    s = re.sub(r"'[^']*'", "S", s)
    s = re.sub(r"\b\d[\d_.x]*\b", "N", s)
    return re.sub(r"\s+", " ", s)[:160]


def _lines(ctx, path):
    try:
        return ctx.repo.lines(path)
    except Exception:
        return []


def _inside(ctx, path, line):
    try:
        for name, first, last in ctx.repo.functions(path):
            if first <= line <= last:
                return name
    except Exception:
        pass
    return None


def _expand(ctx, path, line, text):
    """A statement inside a private helper is reached from the caller that hands it the value:
    report the caller's statement, where a control would have been applied."""
    owner = _inside(ctx, path, line)
    if owner is None or owner in ("run", "__init__", "__call__", "to_dict", "from_dict"):
        return [(path, line, text)]
    try:
        hits = ctx.repo.grep(r"(?:self\.|cls\.|\.)?\b%s\(" % re.escape(owner), glob="*.py")
    except Exception:
        return [(path, line, text)]
    out = []
    for p, n, t in hits:
        if not _wanted(p) or re.match(r"^\s*(def|from|import)\b", t):
            continue
        if p == path and _inside(ctx, p, n) == owner:
            continue
        out.append((p, n, t.strip()))
    return out or [(path, line, text)]


def _pinned_targets(ctx, files, path, consts):
    """Requests in the file that are aimed at a value instead of the constant the file defines."""
    hits = []
    lines = _lines(ctx, path)
    blocks = []
    for number, text in enumerate(lines, 1):
        if not SINK_KIND["request"].search(text) or re.match(r"^\s*(def|class|import|from|@)\b", text):
            continue
        blocks.append(number)
    names = [c for c, _u, _n in consts]
    used = set()
    for number in blocks:
        block = "\n".join(lines[number - 1 : number + 4])
        for c in names:
            if re.search(r"\b%s\b" % c, block):
                used.add(c)
    pinned = [c for c in names if c not in used]
    if not pinned:
        return hits
    for number in blocks:
        target = None
        for offset in range(0, 5):
            index = number - 1 + offset
            if index >= len(lines):
                break
            text = lines[index]
            m = TARGET_ARG.search(text)
            if m is None:
                continue
            value = (m.group(1) or m.group(2)).strip()
            if value and not re.match(r"^[\"']|^[A-Z][A-Z0-9_]*$", value):
                target = (index + 1, text.strip(), value)
            break
        if target is None:
            continue
        index, text, value = target
        if not re.search(r"self\.|kwargs|config|settings|options", text):
            continue
        hits.append((path, index, text,
                     "the project pins this endpoint as %s, but this request is aimed at %s"
                     % (pinned[0], value[:40])))
    return hits


def _block(ctx, path, line):
    """The cited statement together with its continuation lines."""
    lines = _lines(ctx, path)
    if line - 1 >= len(lines):
        return ""
    chunk = [lines[line - 1]]
    indent = len(lines[line - 1]) - len(lines[line - 1].lstrip())
    for offset in range(1, 5):
        index = line - 1 + offset
        if index >= len(lines):
            break
        text = lines[index]
        if not text.strip():
            break
        here = len(text) - len(text.lstrip())
        if here <= indent:
            break
        chunk.append(text)
    return "\n".join(chunk)


def _names(text):
    return set(re.findall(r"[a-z_][\w]*", text)) - {"self", "cls", "str", "int", "float", "len"}


def _guarded(ctx, path, line, name):
    """Is the guard applied to the value this statement uses?
    - in the statement itself (or its continuation lines), or
    - in the three statements above it, or
    - in the assignment that produced one of the variables the statement reads.
    The last test is what distinguishes `title = escape_html(...)` + `<a>{title}` (safe) from
    `title = str(meta[...])` + `<a>{title}` (the defect)."""
    block = _block(ctx, path, line)
    rx = r"(?:\b|\.|self\.)%s\s*\(" % re.escape(name)
    if re.search(rx, block):
        return True
    lines = _lines(ctx, path)
    start = max(0, line - 4)
    above = lines[start : line - 1]
    if re.search(rx, "\n".join(above)):
        return True
    used = _names(block)
    for index in range(max(0, line - 1 - 8), line - 1):
        text = lines[index]
        m = re.match(r"\s*([A-Za-z_][\w]*)\s*(?::[^=]+)?=\s*(.+)", text)
        if m is None or m.group(1) not in used:
            continue
        if re.search(rx, m.group(2)):
            return True
    return False


def run(ctx):
    files = [p for p in ctx.repo.files if _wanted(p)]
    out = []

    # ---- D1 ----
    for path in files:
        consts = []
        for number, text in enumerate(_lines(ctx, path), 1):
            m = CONST_URL.match(text.strip())
            if m:
                consts.append((m.group(1), m.group(2), number))
        if consts:
            out.extend(_pinned_targets(ctx, files, path, consts))

    # ---- D2 ----
    reads = 0
    for path in files:
        for text in _lines(ctx, path):
            reads += len(re.findall(r"os\.environ\s*\[[^\]]*\]\s*(?!=)|os\.getenv\(", text))
    writes = []
    for path in files:
        lines = _lines(ctx, path)
        for number, text in enumerate(lines, 1):
            m = ENV_WRITE.search(text)
            if m is None or re.match(r"^\s*#", text):
                continue
            value = m.group(1).strip()
            if re.match(r"^[\"']|^[A-Z][A-Z0-9_]*$", value):
                continue
            owner = _inside(ctx, path, number)
            src = ""
            try:
                for n2, first, last in ctx.repo.functions(path):
                    if n2 == owner:
                        src = "\n".join(lines[first - 1 : last])
            except Exception:
                src = ""
            if not re.search(r"\*\*\w*kwargs|kwargs\.pop|kwargs\.get|\.pop\(", src):
                continue
            writes.append((path, number, text.strip(),
                           "value %s reaches an environment-variable write from the caller's "
                           "arguments; the project otherwise only reads environment variables"
                           % value[:36]))
    if len(writes) <= 2 and reads >= 1:
        out.extend(writes)

    # ---- D3: guard coverage ----
    guards = {}
    for path in ctx.repo.python_files():
        if not _wanted(path):
            continue
        lines = _lines(ctx, path)
        try:
            funcs = ctx.repo.functions(path)
        except Exception:
            funcs = []
        defined = {n.lower(): (n, f, l) for n, f, l in funcs}
        for low, (name, first, last) in defined.items():
            if len(name) < 5 or not NAME_RX.search(name):
                continue
            kinds = set()
            for rx, ks in NAME_KIND:
                if re.search(rx, low):
                    kinds.update(ks)
            body = "\n".join(lines[first - 1 : last])
            for k, rx in SINK_KIND.items():
                if k in ("log", "env", "path", "request", "html", "sql") and rx.search(body):
                    kinds.add(k)
            if not kinds:
                continue
            info = guards.setdefault(low, {"name": name, "home": set(), "files": set(),
                                           "kinds": kinds, "sites": set()})
            info["home"].add(path)
            info["files"].add(path)
        for number, text in enumerate(lines, 1):
            m = re.match(r"\s*from\s+([\w.]+)\s+import\s+(.+)", text)
            if not m:
                continue
            for name in re.findall(r"[A-Za-z_][\w]*", m.group(2)):
                low = name.lower()
                if low in defined or len(name) < 5 or not NAME_RX.search(name):
                    continue
                kinds = set()
                for rx, ks in NAME_KIND:
                    if re.search(rx, low):
                        kinds.update(ks)
                if not kinds:
                    continue
                info = guards.setdefault(low, {"name": name, "home": set(), "files": set(),
                                               "kinds": kinds, "sites": set()})
                info["files"].add(path)
                info.setdefault("imports", set()).add(path)

    for low, info in sorted(guards.items()):
        name = info["name"]
        try:
            hits = ctx.repo.grep(r"\b%s\s*\(" % re.escape(name), glob="*")
        except Exception:
            continue
        for p, n, t in hits:
            if _wanted(p) and not re.match(r"^\s*(def|from|import)\b", t):
                info["sites"].add((p, n))
                info["files"].add(p)
        info.setdefault("imports", set())

    for low, info in sorted(guards.items()):
        name = info["name"]
        where = {}
        applied = 0
        for path in sorted(info["files"]):
            lines = _lines(ctx, path)
            for number, text in enumerate(lines, 1):
                stripped = text.strip()
                if len(stripped) < 10 or stripped.startswith(("#", '"', "'", "*")):
                    continue
                if re.match(r"^(async\s+)?(def|class|import|from|return|raise|@)\b", stripped):
                    continue
                if not (set(_classify(stripped)) & info["kinds"]):
                    continue
                for p2, n2, t2 in _expand(ctx, path, number, stripped):
                    if _guarded(ctx, p2, n2, name):
                        applied += 1
                    else:
                        where[(p2, n2, t2)] = path
        if applied == 0:
            unused = [
                (p2, n2, t2) for (p2, n2, t2), origin in sorted(where.items())
                if p2 in info["imports"]
            ]
            if len(unused) > 3:
                continue
            for p2, n2, t2 in unused:
                out.append((p2, n2, t2,
                            "%s is imported into this file to guard values of this kind but is "
                            "never called here, although this statement needs it" % name))
            continue
        for (p2, n2, t2), origin in sorted(where.items()):
            if p2 in info["imports"]:
                reason = ("%s is imported into this file and applied to values of this kind "
                          "elsewhere, but this statement does not call it" % name)
            else:
                reason = ("%s is the project's guard for this kind of value and is applied at "
                          "other statements of the same kind, but not here" % name)
            out.append((p2, n2, t2, reason))

    # ---- D4: what a log call writes ----
    # Some log calls in the project wrap what they log (the guard helper, a truncation, a slice);
    # a call that interpolates a whole value verbatim while its siblings wrap theirs is the odd one
    # out. In the fixed version every call wraps, so nothing is reported.
    log_calls = []
    for path in files:
        for number, text in enumerate(_lines(ctx, path), 1):
            if not SINK_KIND["log"].search(text) or re.match(r"^\s*(def|class|import|from|@|#)", text):
                continue
            block = _block(ctx, path, number)
            wrapped = bool(re.search(r"\b\w*(?:%s)\w*\s*\(" % "|".join(GUARD_WORDS), block, re.I))
            if not wrapped:
                wrapped = bool(re.search(r"\[:\s*\d+\]|\btruncat\w*\(|\bshorten\w*\(|"
                                         r"\babbreviat\w*\(", block, re.I))
            values = set(re.findall(r"\{([a-z_][\w.]*)", block)) | \
                set(re.findall(r"%\s*[sd]\s*%\s*\((\w+)", block)) | \
                set(re.findall(r",\s*([a-z_][\w.]*)\s*\)", block))
            log_calls.append({"path": path, "line": number, "text": text.strip(),
                              "wrapped": wrapped, "values": values, "block": block})
    wrapped_values = {}
    for call in log_calls:
        if not call["wrapped"]:
            continue
        for value in call["values"]:
            wrapped_values.setdefault(value.split(".")[0], []).append(
                "%s:%d" % (call["path"], call["line"]))
    for call in log_calls:
        if call["wrapped"]:
            continue
        shared = [v for v in call["values"] if v.split(".")[0] in wrapped_values]
        if not shared:
            continue
        where = ", ".join(wrapped_values[shared[0].split(".")[0]][:3])
        out.append((call["path"], call["line"], call["text"],
                    "%s is truncated or redacted everywhere else it is logged (%s); here the "
                    "whole value goes into the log verbatim" % (shared[0], where)))

    # ---- report, deduplicated ----
    seen = set()
    notes = []
    coverage = {}
    for path, line, text, why in out:
        if (path, line) in seen or len(notes) >= MAX_REPORTS:
            continue
        seen.add((path, line))
        coverage[(path, line)] = why
        try:
            ctx.report(path=path, line_start=line, line_end=line, cwe="CWE-1188",
                       title=why[:110], confidence=70, severity="medium", sink=text[:180],
                       missing_control=why[:200])
            notes.append("%s:%d  %s" % (path, line, why))
        except Exception:
            continue
    ctx.state["coverage"] = coverage
    if notes:
        ctx.note(
            "Control-coverage pass (a deterministic comparison of the project's own statements). "
            "These statements differ from how the project writes the same kind of operation "
            "elsewhere. Read each one and report it at that exact line if the difference really is "
            "a missing control; if the value cannot come from an untrusted source, say so and file "
            "nothing for it.\n" + "\n".join(notes)
        )
    return None
