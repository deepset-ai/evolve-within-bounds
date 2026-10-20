KIND = "tool"
DESCRIPTION = "Search the repository for a regular expression. Returns matching lines as path:line: text. Use this to find patterns (e.g. eval(, resolve_value(), subprocess.run, cursor.execute) across the whole repo before reading files."
PARAMETERS = {"type": "object", "properties": {"pattern": {"type": "string", "description": "a Python regular expression"}}, "required": ["pattern"]}
EXAMPLE = {"pattern": "eval\\(|resolve_value\\(|subprocess\\.run|cursor\\.execute"}

def run(ctx, pattern):
    hits = ctx.repo.grep(pattern, glob="*")
    return "\n".join(f"{p}:{n}: {t.strip()[:160]}" for p, n, t in hits[:200]) or "no match"
