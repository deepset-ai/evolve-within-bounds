KIND = "tool"
DESCRIPTION = (
    "Search the whole repository (code, SQL, YAML, TOML, Markdown) with a regular expression. "
    "Returns 'path:line: text' for each match, with the matched part marked between >>> and <<<. "
    "Use it instead of reading files one by one: one call covers every file. "
    "Alternate a few names with | to cover a family at once."
)
PARAMETERS = {
    "type": "object",
    "properties": {
        "pattern": {
            "type": "string",
            "description": "regular expression, e.g. 'resolve_value|to_dict|requests\\.(get|post)'",
        },
        "glob": {
            "type": "string",
            "description": "optional file filter, e.g. '*.py' or '*.sql'. Default: every file.",
        },
        "ignorecase": {"type": "boolean", "description": "case-insensitive match"},
    },
    "required": ["pattern"],
}
EXAMPLE = {"pattern": "resolve_value|to_dict"}


def run(ctx, pattern, glob=None, ignorecase=False):
    import re as _re

    try:
        flags = _re.IGNORECASE if ignorecase else 0
        rx = _re.compile(pattern, flags)
    except Exception as error:
        return "bad pattern: %s" % error
    hits = ctx.repo.grep(pattern, glob=glob or "*")
    out = []
    for path, line, text in hits[:400]:
        try:
            m = rx.search(text)
        except Exception:
            m = None
        if m is None:
            marker = text[:120]
        else:
            start, end = m.span()
            prefix = "..." if start > 45 else ""
            marker = ">>>" + text[max(0, start - 45) : start] + "<<<"
            marker += text[end : end + 90]
            out.append("%s:%d: %s%s" % (path, line, prefix, marker))
            continue
        out.append("%s:%d: %s" % (path, line, marker))
    if not out:
        return "no match"
    text = "\n".join(out)
    if len(out) >= 400:
        text += "\n... too many matches: narrow the pattern"
    return text
