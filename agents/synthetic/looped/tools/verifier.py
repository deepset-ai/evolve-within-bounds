KIND = "step"
import re

# Refiner + verifier. For every candidate: show the cited statement, the code around it AND how the
# same kind of statement is written elsewhere in the project (the reference form). Ask the model to
# name the reference behaviour and say whether the cited statement differs from it. That question is
# symmetric: it kills findings where the control is present (safe twins) and keeps findings where the
# statement is the one odd member of its family (the planted defect).

CHECK_SYSTEM = """You verify ONE reported security finding in a Python data-pipeline project \
(Haystack components: classes whose run() arguments and documents' content/meta come from untrusted \
sources, whose __init__ parameters come from a pipeline configuration written by a developer, plus \
SQL scripts and packaging files).

You are shown the code around the cited line, and below it the sibling statements of the project: \
other places where the same kind of operation is performed.

Step 1 - reference_behaviour: in one sentence, how this project writes that kind of statement. \
Look for a helper it calls (a containment, encoding, redaction or reference-form helper), a \
parameter it always passes, a binding instead of concatenation, a truncation before a log. If the \
siblings are all written the same way, that way is the reference behaviour. You are also shown the \
project's guard helpers and whether the cited statement calls one: a helper the project calls \
elsewhere but NOT here is the strongest evidence that the control is missing; a statement that does \
call the helper is safe, however dangerous the operation looks.

Step 2 - origin: where does the value used at the cited line come from? Name it in one phrase: a \
run() argument, document content or meta, a file or path name from the input, an HTTP/tool/LLM \
response, an __init__ configuration parameter, or a module constant. Then say whether a check on \
the way (a comparison, a helper call, an allowlist, a resolve) actually constrains it.
Step 3 - control_present: is the control that the finding says is missing actually applied at the \
cited line or on the way to it? Answer true only if the control is applied FULLY, by code, on this \
path, for every value the attacker can choose. Judge the control, not the looks of the statement. \
A statement that has the same SHAPE as its siblings is not thereby safe: when the two ways of \
writing it differ only in which variable is used, decide by origin - a value that traces back to a \
run() argument, a document, a file name or a response is attacker-reachable, and then the control \
is NOT present unless code between its origin and this line enforces it. A check that is easy to \
step over is NOT a control: a prefix test such as startswith on a resolved path, a check that runs \
after the operation, a check that only one of several code paths goes through, a length or type \
check, a validation that only one caller performs.

Step 4 - differs: does the cited statement differ from reference_behaviour, or handle a value of a \
different origin than its siblings, in a way an attacker can exploit?

Step 5 - escalates: does the statement push its value into a stronger context than the siblings do -\
a shell, an interpreter (eval/exec, an import of a computed name, a deserializer), the process \
environment, a command line, a request target that carries a credential - or let a secret travel?

Step 6 - kind: "dataflow" (attacker-reachable data - document content/meta, file text, a tool \
result, an LLM answer, a run() argument, a payload field - reaches a dangerous operation without \
the control), "config" (only a developer-chosen parameter is involved), "robustness" (missing error \
handling, type checks, timeouts, "could raise", style, naming - never a vulnerability), or "none".

Step 6b - never keep a finding that is really one of these: a missing timeout, retry limit, \
try/except or type check (robustness); a caller-supplied file name or path handed to a converter \
that exists to read the caller's files - naming the file to process is the component's normal \
input, not an attack, UNLESS the statement writes or reads outside a configured root or output \
location, or pushes the path into a shell string.

Step 7 - exact_line: the line of the single statement that performs the operation or omits the \
control. Cite the statement that CONSUMES the data: the log call, the request, the write, the \
import, the interpolation - never the enclosing def, an import, or the assignment above it. If the \
defect is that a value is not escaped, validated or resolved, cite the statement that reads that \
value and puts it into the dangerous context. If the cited line is already right, repeat it."""

CHECK_SCHEMA = {
    "type": "object",
    "properties": {
        "reference_behaviour": {"type": "string", "description": "how this project writes this kind of statement"},
        "control_present": {"type": "boolean"},
        "differs": {"type": "boolean"},
        "escalates": {"type": "boolean", "description": "pushes the value into a stronger context than the siblings, or moves a secret"},
        "kind": {"type": "string", "enum": ["dataflow", "config", "robustness", "none"]},
        "exact_line": {"type": "integer"},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
    },
    "required": ["reference_behaviour", "control_present", "differs", "escalates", "kind", "exact_line", "confidence"],
}

MAX_CHECKED = 18
KEEP_TOP = 8


def _shape(text):
    s = text.strip()
    s = re.sub(r"\"[^\"]*\"", "S", s)
    s = re.sub(r"'[^']*'", "S", s)
    s = re.sub(r"\b\d[\d_.x]*\b", "N", s)
    return re.sub(r"\s+", " ", s)[:150]


def _cluster(text):
    m = re.search(r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(", text)
    if m is not None:
        return m.group(1).lower()
    m = re.search(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*", text)
    return m.group(0).lower() if m is not None else ""


def _family(ctx, path, line):
    """How the same kind of statement is written elsewhere in the project."""
    try:
        lines = ctx.repo.lines(path)
    except Exception:
        return ""
    if line - 1 >= len(lines):
        return ""
    name = _cluster(lines[line - 1])
    if len(name) < 4 or "." not in name:
        tail = name.split(".")[-1]
        if len(tail) < 5:
            return ""
        name = tail
    try:
        hits = ctx.repo.grep(re.escape(name), glob="*")
    except Exception:
        return ""
    groups = {}
    for p, n, text in hits[:600]:
        if _cluster(text) != name and name.split(".")[-1] not in _cluster(text):
            continue
        groups.setdefault(_shape(text), []).append((p, n))
    if len(groups) < 2:
        return ""
    ranked = sorted(groups.items(), key=lambda kv: (len(kv[1]), kv[0]))
    out = ["Sibling statements of the project that call %s (grouped by shape, rarest first):" % name]
    for shape, members in ranked[:8]:
        out.append("  %dx  %s" % (len(members), shape))
        for p, n in members[:3]:
            out.append("        %s:%d" % (p, n))
    return "\n".join(out)[:2500]


def _helpers(ctx, path, line):
    """Guard helpers the project defines, and whether the cited statement uses one."""
    if "helpers" not in ctx.state:
        found = []
        for candidate in ctx.repo.python_files():
            if "test" in candidate.lower():
                continue
            try:
                funcs = ctx.repo.functions(candidate)
            except Exception:
                continue
            for name, first, _last in funcs:
                low = name.lower()
                if any(k in low for k in ("url", "path", "quote", "redact", "sanitiz", "contain",
                                          "escape", "valid", "normaliz", "build_", "resolve")) and len(name) > 4:
                    found.append((name, candidate, first))
        ctx.state["helpers"] = found[:25]
    cited = ""
    try:
        cited = ctx.repo.lines(path)[line - 1] if line - 1 < len(ctx.repo.lines(path)) else ""
    except Exception:
        cited = ""
    out = []
    for name, cpath, first in ctx.state["helpers"]:
        try:
            sites = [h for h in ctx.repo.grep(r"\b%s\(" % re.escape(name), glob="*.py") if "test" not in h[0].lower()]
        except Exception:
            continue
        calls = sorted({(p, n) for p, n, _t in sites if n != first})
        if len(calls) < 2:
            continue
        used = bool(re.search(r"\b%s\(" % re.escape(name), cited))
        out.append(
            "guard helper %s (defined %s:%d), called at %d place(s)%s:"
            % (name, cpath, first, len(calls), " -- USED by the cited statement" if used else " -- NOT used by the cited statement")
        )
        for p, n in calls[:6]:
            out.append("        %s:%d" % (p, n))
    return "\n".join(out)[:2200]


def _region(lines, line, before=45, after=45):
    lo = max(1, line - before)
    hi = min(len(lines), line + after)
    return "\n".join("%d | %s" % (i + 1, lines[i][:200]) for i in range(lo - 1, hi))


def _rare_lines(ctx, limit=6000):
    """Locations whose statement is the ONLY member of its shape inside a sink family of >=4
    similar calls. A planted defect is one line edited out of ordinary code, so the edited line is
    usually the unique shape of a family, while ordinary code repeats."""
    if "rare" in ctx.state:
        return ctx.state["rare"]
    sink = re.compile(
        r"request|httpx|urlopen|urllib|client|session|subprocess|popen|system|exec|eval|pickle|"
        r"yaml|marshal|loads|secret|token|api_key|password|credential|environ|getenv|auth|path|"
        r"open|remove|rename|rmtree|write|query|execute|format|template|render|join|replace|"
        r"log|warn|error|info|debug|read_csv|to_dict|from_dict|deserialize|escape|quote|"
        r"sanitiz|redact|valid|verify|timeout|send|import|command|args",
        re.IGNORECASE,
    )
    shapes = {}
    for path in ctx.repo.files:
        low_path = path.lower()
        if not low_path.endswith((".py", ".sql", ".yaml", ".yml", ".toml", ".sh")):
            continue
        if "test" in low_path or "license" in low_path:
            continue
        try:
            lines = ctx.repo.lines(path)
        except Exception:
            continue
        for number, text in enumerate(lines, 1):
            stripped = text.strip()
            if len(stripped) < 12 or stripped.startswith(("#", "//", "*", ":", '"', "'")):
                continue
            if re.match(r"^(async\s+)?(def|class)\b", stripped) or stripped.startswith("return "):
                continue
            match = re.search(r"([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(", stripped)
            if match is None:
                continue
            name = match.group(1).lower()
            if name in ("if", "while", "assert", "for", "lambda", "not", "elif", "with", "yield"):
                continue
            if sink.search(name) is None:
                continue
            if name.endswith(".get") and sink.search(stripped.lower()) is None:
                continue
            shapes.setdefault((name, _shape(stripped)), []).append((path, number))
            limit -= 1
            if limit <= 0:
                break
    by_cluster = {}
    for (cluster, shape), members in shapes.items():
        by_cluster.setdefault(cluster, []).append((shape, members))
    rare = set()
    for cluster, variants in by_cluster.items():
        total = sum(len(m) for _s, m in variants)
        if total < 4 or len(variants) < 2:
            continue
        for _shape_, members in variants:
            if len(members) == 1:
                rare.add(members[0])
    ctx.state["rare"] = rare
    return rare


def run(ctx):
    findings = [f for f in ctx.findings if f.get("path")]
    if not findings:
        return None

    def confidence(finding):
        try:
            return int(finding.get("confidence") or 0)
        except Exception:
            return 0

    def title(finding):
        return str(finding.get("title") or "")

    checked = []
    for finding in findings:
        text = title(finding).lower()
        if confidence(finding) < 15 or text.startswith("reject") or text.startswith("safe"):
            # "reject..." / "safe..." entries are the agent documenting a rejection in the
            # findings list rather than in its summary. Everything else is judged by the model
            # below - a title is never a reason to retract by itself (a dropped timeout argument
            # is one of the real ways a control goes missing).
            try:
                ctx.retract(finding["id"])
            except Exception:
                pass
            continue
        checked.append(finding)

    checked.sort(key=confidence, reverse=True)
    targets = checked[:MAX_CHECKED]
    rest = checked[MAX_CHECKED:]

    cache = {}
    requests = []
    try:
        rare = _rare_lines(ctx)
    except Exception:
        rare = set()
    coverage = ctx.state.get("coverage") or {}
    for finding in targets:
        path = finding["path"]
        line = int(finding.get("line_start") or 1)
        if path not in cache:
            try:
                cache[path] = ctx.repo.lines(path)
            except Exception:
                cache[path] = []
        family = _family(ctx, path, line)
        helpers = _helpers(ctx, path, line)
        census = (
            "Census: this statement is the ONLY one of its shape among the project's similar call "
            "sites - it is the odd one out of its family."
            if (path, line) in rare
            else "Census: this statement has the same shape as other call sites of the same "
            "function in the project (that does not by itself make it safe: check the origin of "
            "the values it passes)."
        )
        found = coverage.get((path, line)) or ""
        extra = (
            "\n\nA deterministic comparison of the project's own statements found this difference "
            "at this very line: %s. Weigh that heavily: the comparison is exact, and it holds only "
            "when the control IS applied at the project's other statements of this kind." % found
            if found
            else ""
        )
        requests.append(
            {
                "prompt": "Finding in %s at line %d:\n%s\n"
                "Claimed missing control: %s\n\nCode around the cited line:\n%s\n\n%s\n%s\n%s%s\n\n"
                "Answer the seven steps."
                % (
                    path,
                    line,
                    title(finding)[:300],
                    (finding.get("missing_control") or finding.get("sink") or "")[:300],
                    _region(cache[path], line),
                    family or "(no sibling statements of this kind found in the project)",
                    helpers or "(no guard helper of the project found)",
                    census,
                    extra,
                ),
                "system": CHECK_SYSTEM,
                "schema": CHECK_SCHEMA,
                "max_tokens": 500,
                "thinking": 300,
            }
        )

    answers = []
    for start in range(0, len(requests), 6):
        batch = requests[start : start + 6]
        try:
            answers.extend(ctx.llm.ask_many(batch))
        except Exception as error:
            answers.extend([{"error": str(error)}] * len(batch))

    survivors = []
    for finding, answer in zip(targets, answers):
        data = answer.get("json")
        if answer.get("error") or not data:
            survivors.append(finding)
            continue
        kind = str(data.get("kind") or "")
        escalates = data.get("escalates") is True
        differs = data.get("differs") is True
        if kind == "none" or data.get("control_present") is True:
            try:
                ctx.retract(finding["id"])
            except Exception:
                pass
            continue
        if kind == "robustness" and not escalates and not differs:
            try:
                ctx.retract(finding["id"])
            except Exception:
                pass
            continue
        if kind == "config" and not differs:
            # A developer-chosen parameter is only a finding when the statement is written
            # differently from the project's own reference form for it (the credential resolver
            # it uses everywhere else, the argument it always passes). If it matches the family,
            # it is a design choice - retract.
            try:
                ctx.retract(finding["id"])
            except Exception:
                pass
            continue
        try:
            exact = int(data.get("exact_line") or 0)
        except Exception:
            exact = 0
        try:
            total = len(ctx.repo.lines(finding["path"]))
        except Exception:
            total = 0
        moved = None
        if exact > 0 and (total == 0 or exact <= total) and abs(exact - int(finding.get("line_start") or 1)) <= 25:
            try:
                ctx.update(finding["id"], line_start=exact, line_end=exact)
                moved = dict(finding)
                moved["line_start"] = exact
            except Exception:
                pass
        conf = data.get("confidence")
        if not isinstance(conf, int):
            conf = confidence(finding)
        conf = max(25, min(95, conf))
        if kind == "dataflow" or (kind == "config" and escalates):
            conf = max(conf, 60)
        try:
            ctx.update(finding["id"], confidence=conf)
        except Exception:
            pass
        moved = moved or dict(finding)
        moved["confidence"] = conf
        survivors.append(moved)

    survivors.extend(rest)
    if len(survivors) > KEEP_TOP:
        rare = _rare_lines(ctx)
        coverage = set((ctx.state.get("coverage") or {}).keys())

        def key(finding):
            loc = (finding.get("path"), int(finding.get("line_start") or 0))
            return (loc not in coverage, loc not in rare, -confidence(finding))

        survivors.sort(key=key)
        for finding in survivors[KEEP_TOP:]:
            try:
                ctx.retract(finding["id"])
            except Exception:
                pass
    return None
