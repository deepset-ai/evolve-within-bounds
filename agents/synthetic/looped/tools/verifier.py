KIND = "step"
DESCRIPTION = "Verify each finding: retract those that are actually safe code containing a control (e.g. ast.literal_eval instead of eval, .to_dict() instead of .resolve_value(), contained_path() instead of a raw join, check_read_only before execute, allowlist/dict lookup, header auth, registered model loader, etc.). Only retract when confident a control neutralizes the reported vulnerability."
PARAMETERS = {}

# Windows of code to show the verifier around each finding, in lines.
_CONTEXT_BEFORE = 80
_CONTEXT_AFTER = 80
_MAX_LINES = 300

# High confidence required to retract a finding: we must be sure a control
# neutralizes the vulnerability. When in doubt, keep the finding.
_RETRACT_CONFIDENCE = 70

_SYSTEM = """You are a security verifier. You are given one candidate finding and the surrounding source code.

Decide whether the code at the reported lines is ACTUALLY vulnerable, or whether it contains a control/sanitization that makes it SAFE (a false positive).

Controls that NEUTRALIZE a vulnerability (mark is_vulnerable=false):
- ast.literal_eval instead of eval on untrusted input
- .to_dict() on a Secret instead of .resolve_value() (serializes the reference, not the plaintext value)
- contained_path() or an explicit path-containment check before a file write
- check_read_only() / a read-only grammar check before cursor.execute(sql)
- check_node_id() / check_resource() validation of an identifier before URL/query interpolation
- trust_remote_code=False and local_files_only=True when loading a model
- Secret.from_env_var() instead of Secret.from_token("literal")
- missing = requested - granted; if missing: raise (require ALL scopes, not any)
- build_url() / a proper URL-building helper instead of raw f-string interpolation of user input
- escape_html() / proper escaping before interpolating into HTML
- parameterized queries or %L instead of string interpolation in SQL
- an explicit allowlist/validation of user input before it reaches a sink
- a dict/allowlist lookup such as job_name_to_id[name] that rejects unknown names (KeyError for invalid input)
- passing credentials in an Authorization header (Bearer) rather than as a URL query parameter
- loading a model via a registered loader rather than import_module on a user-controlled name
- truncating logged content (e.g. json_obj[:100]) so full untrusted content is not logged
- a timeout argument present on an HTTP request (timeout=self.timeout, timeout=90)
- metadata merge order that puts trusted fields last ({**untrusted, **trusted}) so trusted fields win
- escaping Markdown cell-breaking characters (pipe, newline) before rendering a table cell
- an allowlist of approved tables/columns that rejects unknown ones (KeyError or ValueError for invalid input)
- check_origin() / an origin allow-list before fetching a URL from untrusted metadata
- json.loads only (no ast.literal_eval fallback) on model/tool-call output
- use_safetensors=True (default) when loading a model; absence of use_safetensors=False is SAFE
- a missing f-string HTML interpolation (the raw interpolation line was removed in the safe version)

If a control is present that neutralizes the SPECIFIC reported vulnerability, the finding is a false positive: is_vulnerable=false.
If the code is genuinely unprotected (eval on untrusted input, resolve_value of a secret in serialization, a raw path join with user input, execute of unvalidated SQL, etc.), it is a true positive: is_vulnerable=true.

Be conservative: only set is_vulnerable=false when you are confident a control neutralizes the vulnerability. When in doubt, keep the finding (is_vulnerable=true).
"""

_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerable": {"type": "boolean"},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "reason": {"type": "string"}
    },
    "required": ["is_vulnerable", "confidence", "reason"],
    "additionalProperties": False,
}

_USER_TEMPLATE = """Candidate finding:
- path: {path}
- lines: {line_start}-{line_end}
- cwe: {cwe}
- title: {title}

Surrounding code (line numbers are absolute):
{snippet}

Is this code actually vulnerable, or does it contain a control that makes it safe?
Answer with the JSON schema.
"""


def _snippet(ctx, path, line_start, line_end):
    try:
        lines = ctx.repo.lines(path)
    except Exception:
        return ""
    if not lines:
        return ""
    total = len(lines)
    start = max(0, line_start - 1 - _CONTEXT_BEFORE)
    end = min(total, line_end + _CONTEXT_AFTER)
    # Cap the snippet size.
    if end - start > _MAX_LINES:
        # Center the window on the reported lines.
        center = (line_start + line_end) // 2
        start = max(0, min(center - _MAX_LINES // 2, total - _MAX_LINES))
        end = min(total, start + _MAX_LINES)
    out = []
    for i in range(start, end):
        out.append(f"{i+1}: {lines[i]}")
    return "\n".join(out)


def run(ctx):
    findings = list(ctx.findings)
    retracted = 0
    kept = 0
    for f in findings:
        fid = f.get("id")
        path = f.get("path", "")
        line_start = int(f.get("line_start", 0) or 0)
        line_end = int(f.get("line_end", 0) or 0)
        cwe = f.get("cwe", "") or ""
        title = f.get("title", "") or ""

        snippet = _snippet(ctx, path, line_start, line_end)
        if not snippet:
            # Cannot inspect the code: keep the finding.
            kept += 1
            continue

        user = _USER_TEMPLATE.format(
            path=path,
            line_start=line_start,
            line_end=line_end,
            cwe=cwe,
            title=title,
            snippet=snippet,
        )

        try:
            ans = ctx.llm.ask(
                prompt=user,
                system=_SYSTEM,
                schema=_SCHEMA,
                max_tokens=1024,
                thinking=2048,
            )
        except Exception:
            kept += 1
            continue

        if ans.get("error"):
            kept += 1
            continue

        data = ans.get("json") or {}
        is_vuln = bool(data.get("is_vulnerable", True))
        conf = int(data.get("confidence", 0) or 0)
        reason = str(data.get("reason", "") or "")

        if (not is_vuln) and conf >= _RETRACT_CONFIDENCE:
            try:
                ctx.retract(fid)
                retracted += 1
            except Exception:
                kept += 1
        else:
            kept += 1

    ctx.note(f"verifier: retracted {retracted} false-positive findings, kept {kept}")
