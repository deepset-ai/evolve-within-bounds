KIND = "step"
DESCRIPTION = "Hunt the repository for likely vulnerability sink locations and leave targeted notes (file:line + suspected class) for the agent to verify. Greps for a focused set of sink patterns and emits one note per match, so the agent is directed to the exact lines that matter. No per-candidate model triage: fast and deterministic."
PARAMETERS = {}

# Focused sink patterns: (regex, hint class, cwe, priority). Lower priority = more important.
_SINK_PATTERNS = [
    # HTTP requests without a timeout (CWE-400).
    (r"requests\.(get|post|put|patch|delete|head|options|request)\s*\(", "missing_timeout", "CWE-400", 0),
    (r"urllib\.request\.urlopen\s*\(", "missing_timeout", "CWE-400", 0),
    (r"httpx\.(get|post|put|patch|delete|request)\s*\(", "missing_timeout", "CWE-400", 0),
    (r"aiohttp\.ClientSession\.\w+\s*\(", "missing_timeout", "CWE-400", 0),
    # Untrusted data turned into a data source (CWE-918 / arbitrary file read).
    (r"pd\.read_csv\s*\(", "read_csv_untrusted", "CWE-918", 1),
    (r"pandas\.read_csv\s*\(", "read_csv_untrusted", "CWE-918", 1),
    # Caller-controlled metadata overriding trusted fields (CWE-915).
    (r"meta=\{\*\w+,\s*\*\w+\}", "meta_override", "CWE-915", 2),
    # SQL filter operator bypass (CWE-943).
    (r"operator\.startswith\(\"\$\"\)", "sql_operator_bypass", "CWE-943", 3),
    # Template source built from untrusted document text (CWE-94).
    (r"string\.Template|\bTemplate\s*\(", "template_injection", "CWE-94", 4),
    (r"\.replace\(\"\{document_text\}", "template_injection", "CWE-94", 4),
    # Secret appended to a URL as a query parameter (CWE-598).
    (r"access_token\s*=", "credential_in_url", "CWE-598", 5),
    (r"api_key\s*=\s*.*resolve_value\(\)", "credential_in_url", "CWE-598", 5),
    # User input interpolated into a URL/path/query (CWE-918 / CWE-22 / CWE-73).
    (r"f\".*\{.*\}", "url_interpolation", "CWE-918", 6),
    (r"f'.*\{.*\}'", "url_interpolation", "CWE-918", 6),
    # Logging untrusted content verbatim (CWE-117).
    (r"logger\.(warning|debug|info|error|exception|critical)\s*\(", "log_untrusted", "CWE-117", 7),
    (r"print\s*\(", "log_untrusted", "CWE-117", 7),
    # Deserialization of untrusted data (CWE-502).
    (r"ast\.literal_eval\s*\(", "literal_eval", "CWE-502", 8),
    (r"pickle\.loads|yaml\.load\s*\(", "deserialization", "CWE-502", 8),
    # import_module on a user-controlled name (CWE-470).
    (r"import_module\s*\(", "import_module", "CWE-470", 9),
    # resolve_value of a secret (CWE-798).
    (r"resolve_value\(\)", "resolve_value", "CWE-798", 10),
    # SQL execute (CWE-943).
    (r"cursor\.execute\s*\(|\.execute\s*\(.*sql", "sql_execute", "CWE-943", 11),
    # Subprocess (CWE-78).
    (r"subprocess\.(run|Popen|call)\s*\(", "subprocess", "CWE-78", 12),
    (r"os\.system\s*\(", "subprocess", "CWE-78", 12),
    # Model loading (CWE-...).
    (r"trust_remote_code\s*=\s*True", "model_loading", "CWE-...", 13),
    (r"local_files_only\s*=\s*False", "model_loading", "CWE-...", 13),
    # Hard-coded secret (CWE-798).
    (r"Secret\.from_token\s*\(", "hardcoded_secret", "CWE-798", 14),
]

_MAX_NOTES = 30


def run(ctx):
    candidates = []  # (priority, path, line, text, hint, cwe)
    seen = set()
    for pattern, hint, cwe, priority in _SINK_PATTERNS:
        try:
            hits = ctx.repo.grep(pattern, glob="*")
        except Exception:
            continue
        for p, n, t in hits:
            key = (p, n)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((priority, p, n, t, hint, cwe))

    if not candidates:
        ctx.note("hunter: no sink candidates found")
        return

    candidates.sort(key=lambda c: c[0])
    candidates = candidates[:_MAX_NOTES]

    notes = []
    for priority, p, n, t, hint, cwe in candidates:
        notes.append(
            f"HUNTER: {p}:{n} — suspected {hint} ({cwe}). Sink: {t.strip()[:140]}"
        )

    ctx.note("hunter: likely vulnerability locations to verify:\n" + "\n".join(notes))
