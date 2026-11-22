"""Security, WAF, and Injection Defense Module for ThreatWatch.

Provides multi-layered defense against SQL injection, NoSQL operator injection,
and regex-based injection across all HTTP endpoints, form inputs, query parameters,
and JSON bodies.
"""
import logging
import re
from typing import Any, Optional, Tuple

log = logging.getLogger("threatwatch.security")

# ---------------------------------------------------------------- SQL Injection Patterns
# Aligned with OWASP Core Rule Set (CRS) and industry WAF signatures.
SQL_INJECTION_PATTERNS = [
    # 1. Classic boolean tautologies / auth bypass (e.g. ' OR '1'='1', " OR ""=", ' OR 1=1, admin' OR 'x'='x')
    re.compile(r"""(?i)(?:\b(?:or|and)\b\s+['"]?[\w\d]+['"]?\s*=\s*['"]?[\w\d]+)"""),
    re.compile(r"""(?i)(?:\b(?:or|and)\b\s+(?:true|1\s*=\s*1|0\s*=\s*0)\b)"""),

    # 2. UNION-based SQLi (e.g. UNION SELECT, UNION ALL SELECT)
    re.compile(r"""(?i)(?:\bunion\b\s+(?:all\s+)?\bselect\b)"""),

    # 3. Stacked queries & DDL/DML injection (e.g. ; DROP TABLE, ; DELETE FROM, ; INSERT INTO)
    re.compile(r"""(?i)(?:;\s*(?:drop|alter|create|truncate|delete\s+from|insert\s+into|update\s+\w+\s+set)\b)"""),
    re.compile(r"""(?i)(?:\b(?:drop\s+table|drop\s+database|truncate\s+table)\b)"""),

    # 4. SQL comments combined with quotes or keywords (e.g. ' OR 1=1 --, admin'--, ' /*)
    re.compile(r"""(?:['"][^'"\n\r]*(?:--|/\*|#))"""),
    re.compile(r"""(?:^\s*(?:--|#|/\*).*(?:select|union|insert|update|delete|drop))""", re.IGNORECASE),

    # 5. Time-based blind SQLi & sleep functions (e.g. SLEEP(5), WAITFOR DELAY, BENCHMARK(1000000))
    re.compile(r"""(?i)(?:\b(?:sleep\s*\(\s*\d+\s*\)|waitfor\s+delay\b|benchmark\s*\(\s*\d+))"""),

    # 6. Outfile / file reading / system command execution
    re.compile(r"""(?i)(?:\b(?:load_file\s*\(|into\s+(?:out|dump)file\b|exec(?:ute)?\s+(?:xp_|sp_)))"""),

    # 7. Error-based SQLi functions (e.g. extractvalue, updatexml)
    re.compile(r"""(?i)(?:\bextractvalue\s*\(|\bupdatexml\s*\()"""),
]

# Pattern matching NoSQL operator injection keys (e.g. $where, $gt, $ne, $regex)
NOSQL_OPERATOR_PATTERN = re.compile(r"""^\$([a-zA-Z0-9_]+)""")


def is_sql_injection(value: Any) -> Tuple[bool, Optional[str]]:
    """Inspect a value recursively for known SQL injection patterns and signatures.

    Returns:
        (True, matched_pattern_text) if an SQL injection pattern is detected.
        (False, None) if the input is benign.
    """
    if value is None:
        return False, None

    if isinstance(value, str):
        val_str = value.strip()
        if not val_str:
            return False, None

        for pattern in SQL_INJECTION_PATTERNS:
            match = pattern.search(val_str)
            if match:
                return True, match.group(0)
        return False, None

    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(k, str):
                if NOSQL_OPERATOR_PATTERN.match(k):
                    return True, f"NoSQL operator '{k}'"
                matched, pat = is_sql_injection(k)
                if matched:
                    return True, pat
            matched, pat = is_sql_injection(v)
            if matched:
                return True, pat
        return False, None

    if isinstance(value, (list, tuple, set)):
        for item in value:
            matched, pat = is_sql_injection(item)
            if matched:
                return True, pat
        return False, None

    return False, None


def sanitize_search_query(query_str: str) -> str:
    """Escape regex special characters to prevent regex/NoSQL injection."""
    if not query_str or not isinstance(query_str, str):
        return ""
    return re.escape(query_str.strip())
