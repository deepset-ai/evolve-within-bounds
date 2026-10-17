KIND = "step"
# Hunter: one cheap model pass over EVERY file, in condensed form (structure + sink lines), so no
# file is left unread and big files are covered too. Reports candidates for the verifier.

RUBRIC = """You are reviewing part of ONE file of a Python project that builds data pipelines \
(Haystack components: classes with a run() whose arguments come from other components and an \
__init__ whose parameters come from a pipeline configuration file, plus helpers, SQL scripts and \
packaging files). Long files are shown condensed: definition lines plus the lines where a secret, \
a request, a query, a path, a log call, a template or an interpreter appears, with their line \
numbers and a little context. Judge the lines you are shown; the line numbers are the real ones.

Report a candidate ONLY where a specific security control is missing at a specific statement. \
Name the missing control in one phrase. If the statement already applies the control, there is \
nothing to report - do not invent a weaker issue in the same lines.

Kinds worth a look (each hinges on a control absent at one statement):
- a credential resolved from a literal string in a default argument (`Secret.from_token("...")`, \
`api_key="..."`, `token=os.getenv(...) or "..."`) where every other credential in the project is \
resolved from the environment: cite the line of that default argument, not the line that later \
sends the credential;
- a secret serialized in plaintext, logged, put in a command line, an environment variable or a \
URL query, or sent over plain http. A serialization site counts: a component that hands a secret to \
`default_to_dict(...)`/`to_dict()` through `resolve_value()` writes the plaintext into the \
serialized pipeline, where every sibling component serializes it with `.to_dict()` - cite the \
`default_to_dict(...)` line;
- untrusted text reaching an interpreter or an API: eval/exec (an unused `import ast` in that same \
file points at the reference form `ast.literal_eval`), import of a computed name, \
pickle/yaml.load, SQL or a query built by concatenation/replace/format instead of binding, \
template source built from data, a shell string built by joining a command with its arguments, \
HTML built by concatenation, a path built from input, a request whose target comes from input;
- a string that arrives as a run() argument or document field handed to a loader that treats it as \
a path, URL or source (`pd.read_csv(x)`, `open(x)`, `json.load(x)`) where the project's other sites \
wrap such a string in an in-memory stream: cite the loader call;
- a value from a document, a file, a tool result, an LLM answer or a run() argument used where a \
validated or trusted value is expected: role, flag, index, identifier, URL, table or collection \
name taken from the payload; caller data merged so it overrides fields the component computed - \
`{**computed, **caller_meta}`, where the reference form puts the caller data FIRST so the computed \
keys win: cite the unpacking line;
- the project defines a helper that encodes, contains, redacts or validates a value and calls it at
  some of the places that need it - your candidate is a place of the same kind that does not;
- untrusted content written to a log or to an exception message verbatim: that is a finding at the \
line of the log call, even when a more dramatic-looking parse sits a few lines above it;
- an output path or directory derived from the input's own path (its parent, its name) instead of
  the configured output location, where the rest of the code writes to the configured location;
- an argument the project always passes and here is dropped: `timeout=self.timeout` missing from a
  request in a component that stores `self.timeout` and passes it at its other call sites. That is a
  candidate; a timeout the project never sets anywhere is not.

Rules:
- Before reporting a candidate, ask: does this statement differ from how the project writes the \
same kind of statement elsewhere (the helper it calls, the argument it passes, the way it builds \
the value)? A statement that already applies the control is NOT a candidate, even if the operation \
looks dangerous - do not report a weaker issue in the same lines instead.
- line_start/line_end = the line of the statement that performs the operation or omits the control, \
never the enclosing def, the import, or the assignment above it.
- Cite where the untrusted data is CONSUMED, not where it is read or parsed: if the issue is that \
content reaches a log, an output, a request or a command, cite that call - not the parse or the \
assignment a few lines above. If the issue is that a value is not checked, cite the use, not the \
check that is absent somewhere else.
- Not a finding: missing try/except or type checks, "could raise", debug-level logging, a \
hardcoded default URL, dependency versions, naming, dead code, a timeout the project never sets \
anywhere or a missing retry limit (robustness, not a vulnerability), a caller-supplied file name or \
path handed to a tool that is meant to read the caller's files.
- At most 3 candidates, only concrete ones. If nothing qualifies, return an empty list."""

SCHEMA = {
    "type": "object",
    "properties": {
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line_start": {"type": "integer"},
                    "line_end": {"type": "integer"},
                    "cwe": {"type": "string", "description": "e.g. CWE-22"},
                    "title": {"type": "string", "description": "one line, says what is missing"},
                    "control": {"type": "string", "description": "the control that is absent here"},
                    "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
                },
                "required": ["line_start", "title", "control", "confidence"],
            },
        }
    },
    "required": ["candidates"],
}

MARKERS = [
    "resolve_value", "to_dict", "from_dict", "secret", "environ", "getenv", "token", "api_key",
    "apikey", "password", "credential", "authorization", "bearer",
    "subprocess", "popen", "os.system", "shell", "cmd", "args", "exec", "eval", "pickle",
    "yaml.load", "yaml.unload", "import_module", "__import__", "marshal", "shelve",
    "requests.", "httpx.", "urlopen", "urllib", "client.", "query", "connect", "send", "post(",
    "path(", "open(", "os.path", "listdir", "glob", "remove", "rmtree", "write",
    "format(", "%s", "%d", ".replace(", ".join(", "template", "jinja", "render", "str.format",
    "select ", "insert ", "update ", "delete ", "where ", "sparql", "cypher", "sql",
    "logger.", "log.", "print(", "warning", "info(", "error(", "exc_info", "traceback",
    "read_csv", "read_excel", "read_parquet", "stringio", "io.open",
    "md5", "sha1", "verify=", "timeout", "escape", "sanitiz", "redact", "allow", "startswith",
    "../", "abspath", "realpath", "relpath", "unquote", "base64", "html", "xml",
    "kwargs", "meta", "role", "index", "url", "uri", "endpoint", "host", "table", "collection",
    "content", "text", "answer", "prompt", "instruction", "system", "merge", "update(",
]
WEAK_MARKERS = ["def run", "def __init__", "def to_dict", "def from_dict", "class ", "import "]

CHUNK_LINES = 150
MAX_CHUNKS = 30
PRIORITY = ("src/", "lib/", "components/", "app/", "scripts/", "init-")
CODE_EXT = (".py", ".sql", ".yaml", ".yml", ".toml", ".jinja2", ".j2", ".json", ".sh", ".cfg", ".ini")


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


def _condensed(lines):
    keep = [False] * (len(lines) + 2)
    for i, text in enumerate(lines):
        low = text.lower()
        if any(m in low for m in MARKERS):
            keep[i] = True
            for j in (i + 1, i + 2):
                if j < len(lines):
                    keep[j] = True
        elif any(m in low for m in WEAK_MARKERS) or text.rstrip().endswith((",", "(")):
            keep[i] = True
    out = []
    previous = -3
    for i, text in enumerate(lines):
        if not keep[i]:
            continue
        if i > previous + 1:
            out.append("    ...")
        out.append("%d | %s" % (i + 1, text.rstrip()[:190]))
        previous = i
    return out


def run(ctx):
    files = [f for f in ctx.repo.files if _wanted(f)]
    files.sort(key=lambda p: (0 if p.startswith(PRIORITY) else 1, len(p), p))

    chunks = []
    for path in files:
        try:
            lines = ctx.repo.lines(path)
        except Exception:
            continue
        if not lines:
            continue
        body = _condensed(lines)
        if not body:
            body = ["%d | %s" % (i + 1, lines[i][:190]) for i in range(min(len(lines), 40))]
        if len(body) <= CHUNK_LINES:
            chunks.append((path, body, 1, len(lines)))
        else:
            for start in range(0, len(body), CHUNK_LINES - 10):
                chunks.append((path, body[start : start + CHUNK_LINES], 1, len(lines)))
                if len(chunks) >= MAX_CHUNKS:
                    break
        if len(chunks) >= MAX_CHUNKS:
            break

    requests = []
    for path, body, _a, total in chunks:
        requests.append(
            {
                "prompt": "File: %s (%d lines, condensed)\n\n%s\n\nReturn the candidates."
                % (path, total, "\n".join(body)),
                "system": RUBRIC,
                "schema": SCHEMA,
                "max_tokens": 500,
                "thinking": 200,
            }
        )

    seen = {}
    found = 0
    notes = []
    for start in range(0, len(requests), 10):
        batch = requests[start : start + 10]
        try:
            answers = ctx.llm.ask_many(batch)
        except Exception as error:
            answers = [{"error": str(error)}] * len(batch)
        for index, answer in enumerate(answers):
            path = chunks[start + index][0]
            data = answer.get("json") or {}
            for cand in (data.get("candidates") or [])[:3]:
                try:
                    line = int(cand.get("line_start") or 0)
                except Exception:
                    continue
                if line <= 0:
                    continue
                try:
                    end = max(int(cand.get("line_end") or line), line)
                except Exception:
                    end = line
                if seen.get(path, 0) >= 4:
                    continue
                seen[path] = seen.get(path, 0) + 1
                cwe = str(cand.get("cwe") or "").strip()
                if cwe and not cwe.upper().startswith("CWE"):
                    cwe = "CWE-" + cwe
                conf = cand.get("confidence")
                if not isinstance(conf, int):
                    conf = 60
                control = str(cand.get("control") or "")[:160]
                try:
                    ctx.report(
                        path=path,
                        line_start=line,
                        line_end=end,
                        cwe=cwe or "CWE-1188",
                        title=str(cand.get("title") or "")[:120],
                        confidence=max(40, min(90, conf)),
                        severity="medium",
                        sink=control,
                        missing_control=control,
                    )
                    found += 1
                    notes.append("%s:%d  %s" % (path, line, str(cand.get("title") or "")[:70]))
                except Exception:
                    continue

    if found:
        ctx.note(
            "A first pass over every file reported %d candidate location(s) below. They are guesses: "
            "some are the real defect, some are safe code that merely looks like one. For each one "
            "that matters, read the code around it and report it only if the control really is "
            "missing, with the exact line. Say nothing about the ones you reject.\n" % found
            + "\n".join(notes[:40])
        )
    else:
        ctx.note(
            "A first pass over every file found no candidate; it can still miss things. Review the "
            "files yourself, starting with those that take input from documents, from run() "
            "arguments or from the pipeline configuration."
        )
    return None
