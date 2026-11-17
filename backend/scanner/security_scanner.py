"""Security scanning: multi-language regex rules + Python AST taint-lite checks +
optional Bandit / Semgrep integration when those tools are installed."""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from .file_scanner import SourceFile
from .models import SEVERITY_DOWNGRADE, Finding
from .rules import Rule, run_line_rules

I = re.IGNORECASE
PY = {"python"}
JS = {"javascript", "typescript", "vue", "svelte", "html"}
JVM = {"java", "kotlin", "scala"}

# ---------------------------------------------------------------- secrets
SECRET_NAME = (
    r"(?:[\w.-]*?(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|(?:auth|access|api|secret|bearer|refresh|github|slack)[_-]?token|db[_-]?pass)[\w-]*)"
)
PLACEHOLDER = re.compile(
    r"^(\$\{.*\}|\{\{.*\}\}|<[^>]*>|%\(.*\)s|\$[A-Z_]+|\*+|x+|\.+|null|none|true|false|undefined)$|"
    r"your[_-]|example|placeholder|dummy|redacted|process\.env|os\.environ|getenv|"
    r"^(password|secret|token|pwd|passwd|api[_-]?key)$",
    I,
)


def _real_secret(m: re.Match) -> bool:
    value = m.group("value").strip()
    return len(value) >= 4 and not PLACEHOLDER.search(value) and " " not in value.strip()


def _real_db_secret(m: re.Match) -> bool:
    return not PLACEHOLDER.search(m.group("value"))


SECRET_RECO = (
    "Remove the secret from source code, rotate it immediately, and load it at runtime from an "
    "environment variable or a secrets manager (Vault, AWS Secrets Manager, Doppler, etc.)."
)

SECURITY_RULES: list[Rule] = [
    Rule("hardcoded-secret", "Hardcoded password / secret", "security", "high",
         re.compile(SECRET_NAME + r"""["']?\s*(?::\s*[\w\[\]|. ]+?\s*)?(?:=|:|=>|:=)\s*[bfr]?["'](?P<value>[^"'\n]{4,})["']""", I),
         "A credential is written directly in source code. Anyone with access to the repository "
         "(or its history) can read and abuse it.",
         SECRET_RECO, kinds=("code", "config"), cwe="CWE-798", skip_comments=False,
         downgrade_in_tests=True, validator=_real_secret),
    Rule("hardcoded-secret-config", "Secret stored in configuration file", "security", "high",
         re.compile(r"^\s*(?:export\s+)?" + SECRET_NAME + r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'#]{4,})", I),
         "A credential is committed inside a configuration file.", SECRET_RECO,
         kinds=("config",), cwe="CWE-798", validator=_real_secret, downgrade_in_tests=True),
    Rule("aws-access-key", "AWS access key ID committed", "security", "critical",
         re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
         "An AWS access key ID is present. Paired with a secret key it grants access to cloud resources.",
         SECRET_RECO, kinds=("code", "config"), cwe="CWE-798", confidence="high", skip_comments=False),
    Rule("private-key", "Private key committed", "security", "critical",
         re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
         "A private key is embedded in the repository.", SECRET_RECO,
         kinds=("code", "config"), cwe="CWE-321", confidence="high", skip_comments=False),
    Rule("api-token", "Cloud / SaaS API token committed", "security", "critical",
         re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_\-]{35}|"
                    r"sk_live_[0-9a-zA-Z]{20,}|gsk_[A-Za-z0-9]{40,}|sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"),
         "A token matching a known provider format (GitHub, Slack, Google, Stripe, Groq, OpenAI) was found.",
         SECRET_RECO, kinds=("code", "config"), cwe="CWE-798", confidence="high", skip_comments=False),
    Rule("db-url-credentials", "Database URL with embedded credentials", "security", "high",
         re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:\s/\"']+:(?P<value>[^@\s/\"']+)@", I),
         "A connection string contains a username and password.", SECRET_RECO,
         kinds=("code", "config"), cwe="CWE-798", validator=_real_db_secret, skip_comments=False),
    Rule("jwt-token", "Hardcoded JWT", "security", "medium",
         re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
         "A JSON Web Token is hardcoded. It may grant access until it expires.", SECRET_RECO,
         kinds=("code", "config"), cwe="CWE-798"),

    # ------------------------------------------------------------ injection
    Rule("sql-injection", "Possible SQL injection (string-built query)", "security", "critical",
         re.compile(r"""["'`][^"'`]*\b(?:select\s.+?\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"'`]*["'`]\s*(?:\+|%\s*[\w(]|\.format\s*\()""", I),
         "A SQL statement is built by concatenating/formatting values into the query string. If any "
         "value comes from user input an attacker can change the query (read/modify/delete data).",
         "Use parameterized queries / prepared statements (e.g. cursor.execute(\"... WHERE id = %s\", (user_id,)), "
         "PreparedStatement, or your ORM's query builder). Never concatenate input into SQL.",
         cwe="CWE-89", confidence="high"),
    Rule("sql-injection", "Possible SQL injection (interpolated query)", "security", "critical",
         re.compile(r"""(?:\bf["']|`)[^"'`]*\b(?:select\s.+?\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"'`]*(?:\{|\$\{)""", I),
         "A SQL statement uses string interpolation (f-string / template literal) to insert values.",
         "Use parameterized queries / prepared statements instead of string interpolation.",
         cwe="CWE-89", confidence="high"),
    Rule("command-injection", "OS command execution with a shell", "security", "high",
         re.compile(r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|"
                    r"\bchild_process\.exec(?:Sync)?\s*\(|\bexecSync\s*\(|Runtime\.getRuntime\(\)\.exec\s*\(|"
                    r"\b(?:shell_exec|passthru|proc_open)\s*\("),
         "Commands executed through a shell are vulnerable to command injection when any part of the "
         "command string is influenced by input.",
         "Use an argument list without a shell (subprocess.run([...], shell=False), execFile/spawn, "
         "ProcessBuilder) and validate inputs against an allow-list.",
         cwe="CWE-78"),
    Rule("code-injection", "Dynamic code execution (eval/exec)", "security", "high",
         re.compile(r"(?<![\w.])(?:eval|exec)\s*\(|\bnew\s+Function\s*\("),
         "eval/exec run arbitrary code. If the argument can be influenced by a user this is remote code execution.",
         "Remove eval/exec. Parse data with a safe parser (json.loads, ast.literal_eval, JSON.parse) or use a dispatch table.",
         languages=PY | JS | {"php", "ruby"}, cwe="CWE-95"),
    Rule("insecure-deserialization", "Insecure deserialization", "security", "high",
         re.compile(r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|"
                    r"\byaml\.load\s*\((?![^)]*SafeLoader)|\bnew\s+ObjectInputStream\s*\(|\bunserialize\s*\(|"
                    r"\bBinaryFormatter\s*\(|\bjsonpickle\.decode\s*\("),
         "Deserializing untrusted data with pickle/ObjectInputStream/unserialize can execute attacker-controlled code.",
         "Use a data-only format such as JSON, or yaml.safe_load. Never deserialize data from untrusted sources.",
         cwe="CWE-502"),
    Rule("path-traversal", "Possible path traversal (file path from request)", "security", "high",
         re.compile(r"\b(?:open|send_file|send_from_directory|FileResponse)\s*\([^)]*\brequest\.|"
                    r"\b(?:readFile\w*|createReadStream|sendFile|unlink\w*)\s*\([^)]*\breq\.(?:params|query|body)"),
         "A file path is built from request data, letting an attacker read or write files outside the intended folder (../../etc/passwd).",
         "Resolve the path, verify it stays inside an allowed base directory, and prefer IDs mapped to server-side paths.",
         cwe="CWE-22"),
    Rule("ssrf", "Possible SSRF (outbound request to user-supplied URL)", "security", "high",
         re.compile(r"\brequests\.(?:get|post|put|request)\s*\(\s*request\.|\b(?:fetch|axios\.\w+|got|http\.get)\s*\(\s*req\.(?:query|body|params)|"
                    r"\burlopen\s*\(\s*request\."),
         "The server fetches a URL controlled by the client, which can be abused to reach internal services or cloud metadata endpoints.",
         "Validate the URL against an allow-list of hosts and block private / link-local IP ranges.",
         cwe="CWE-918"),
    Rule("xss", "Possible XSS (unescaped HTML injection)", "security", "medium",
         re.compile(r"\.innerHTML\s*=(?!=)|\bouterHTML\s*=(?!=)|dangerouslySetInnerHTML|\bdocument\.write\s*\(|"  # codeguard: ignore (rule definition)
                    r"\|\s*safe\b|\bmark_safe\s*\(|\bv-html\s*="),
         "HTML is inserted without escaping. If it contains user-controlled data an attacker can run scripts in other users' browsers.",
         "Render text with textContent / framework escaping, or sanitize HTML with a library such as DOMPurify / bleach.",
         languages=JS | PY | {"php"}, kinds=("code",), cwe="CWE-79", skip_tests=True),

    # ------------------------------------------------------------ crypto / transport
    Rule("weak-hash", "Weak hashing algorithm (MD5/SHA-1)", "security", "medium",
         re.compile(r"\bhashlib\.(?:md5|sha1)\s*\(|\bhashlib\.new\(\s*['\"](?:md5|sha1)|MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|"
                    r"createHash\(\s*['\"](?:md5|sha1)['\"]|\bDigestUtils\.(?:md5|sha1)|(?<![\w.])md5\s*\(", I),
         "MD5 and SHA-1 are broken for security purposes (collisions; fast to brute-force for passwords).",
         "Use SHA-256+ for integrity, and bcrypt/argon2/scrypt for passwords. If used for a non-security checksum, mark it (usedforsecurity=False).",
         cwe="CWE-328"),
    Rule("tls-verification-disabled", "TLS certificate verification disabled", "security", "high",
         re.compile(r"\bverify\s*=\s*False\b|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|"
                    r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|\bssl\.CERT_NONE\b|_create_unverified_context"),  # codeguard: ignore (rule definition)
         "Disabling certificate verification allows man-in-the-middle attackers to read and modify traffic.",
         "Keep verification on. For private CAs pass the CA bundle path instead of disabling checks.",
         cwe="CWE-295", kinds=("code", "config")),
    Rule("insecure-random", "Non-cryptographic randomness used for a secret", "security", "medium",
         re.compile(r"(?:\brandom\.(?:random|randint|choice|choices|randrange)\s*\(|Math\.random\(\)).*\b(?:token|password|secret|otp|salt|nonce|session|key)\b|"
                    r"\b(?:token|password|secret|otp|salt|nonce|session_id)\w*\s*=.*(?:\brandom\.(?:random|randint|choice|choices)|Math\.random\(\))", I),
         "The random generator used is predictable and must not produce tokens, passwords or OTPs.",
         "Use the secrets module (Python), crypto.randomBytes / crypto.randomUUID (Node) or SecureRandom (Java).",
         cwe="CWE-338"),
    Rule("jwt-verification-disabled", "JWT signature verification disabled", "security", "critical",
         re.compile(r"verify_signature['\"]?\s*:\s*False|algorithms\s*=\s*\[\s*['\"]none['\"]|\.decode\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true", I),
         "Tokens are accepted without validating the signature/expiry, so anyone can forge them.",
         "Always verify JWT signatures with an explicit algorithm allow-list and validate expiry.",
         cwe="CWE-347"),

    # ------------------------------------------------------------ configuration
    Rule("debug-enabled", "Debug mode enabled", "security", "medium",
         re.compile(r"\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b|app\.debug\s*=\s*True"),
         "Debug mode exposes stack traces, internal state and sometimes an interactive console to attackers.",
         "Drive debug mode from an environment variable and make sure it is off in production.",
         cwe="CWE-489"),
    Rule("cors-wildcard", "CORS allows any origin", "security", "medium",
         re.compile(r"allow_origins\s*=\s*\[\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|"
                    r"\borigin\s*:\s*['\"]\*['\"]|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|AllowAnyOrigin\(\)"),
         "Any website can call this API from a victim's browser. Combined with credentials this leaks user data.",
         "Restrict CORS to the exact front-end origins you own.",
         cwe="CWE-942", kinds=("code", "config")),
    Rule("sensitive-logging", "Sensitive value written to logs", "security", "medium",
         re.compile(r"\b(?:print|console\.(?:log|info|debug)|logger\.\w+|logging\.\w+|log\.\w+|System\.out\.println)\s*\(.*\b(?:password|passwd|secret|api_key|apikey|token|credit_card|ssn)\b", I),
         "Secrets or personal data in logs are visible to anyone with log access and are often retained for a long time.",
         "Never log credentials. Mask sensitive fields before logging.",
         cwe="CWE-532"),
    Rule("permissive-file-permissions", "World-writable file permissions", "security", "medium",
         re.compile(r"chmod\s*\(?[^)\n]*\b0?o?777\b|chmod\s+(?:-R\s+)?777"),
         "777 permissions let any user on the machine modify or replace the file.",
         "Grant the minimum permissions required (e.g. 0o640 / 0o750).",
         cwe="CWE-732", kinds=("code", "config")),
]


# ---------------------------------------------------------------- Python AST checks
SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra"}


class _PySecurityVisitor(ast.NodeVisitor):
    def __init__(self, f: SourceFile):
        self.f = f
        self.findings: list[Finding] = []

    def _is_dynamic_string(self, node: ast.AST) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
        return False

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in SQL_METHODS and node.args:
            if self._is_dynamic_string(node.args[0]):
                self.findings.append(Finding(
                    "sql-injection", "SQL injection: query built dynamically and passed to execute()",
                    "security", "critical", self.f.path, node.lineno,
                    "The query passed to the database driver is built with string formatting/concatenation. "
                    "Any user-controlled value can rewrite the query.",
                    "Pass values as parameters: cursor.execute(\"SELECT ... WHERE id = %s\", (user_id,)).",
                    snippet=self.f.line(node.lineno).strip(), source="ast", confidence="high", cwe="CWE-89"))
        self.generic_visit(node)


def python_ast_security(files: list[SourceFile]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        if f.language != "python":
            continue
        try:
            tree = ast.parse(f.text)
        except (SyntaxError, ValueError):
            continue
        v = _PySecurityVisitor(f)
        v.visit(tree)
        out.extend(v.findings)
    return out


# ---------------------------------------------------------------- project-level checks
def project_security_checks(files: list[SourceFile]) -> list[Finding]:
    out = []
    for f in files:
        name = Path(f.path).name
        if f.language == "dotenv" and not any(t in name for t in ("example", "sample", "template")):
            out.append(Finding(
                "env-file-committed", "Environment file committed to the repository", "security", "high",
                f.path, 1,
                ".env files usually hold real credentials and should never be committed.",
                "Delete the file from the repository (and history), rotate its secrets, add .env to .gitignore "
                "and commit a .env.example with placeholder values instead.",
                cwe="CWE-538", confidence="high"))
    return out


# ---------------------------------------------------------------- external tools
def _module_available(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def run_bandit(root: str, files: list[SourceFile]) -> tuple[list[Finding], str]:
    if not any(f.language == "python" for f in files):
        return [], "skipped (no Python files)"
    if not _module_available("bandit"):
        return [], "skipped (bandit not installed)"
    cmd = [sys.executable, "-m", "bandit", "-r", root, "-f", "json", "-q",
           "-x", ",".join(f"*/{d}/*" for d in ("node_modules", ".venv", "venv", ".git"))]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        return [], f"failed ({exc.__class__.__name__})"
    sev = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    out = []
    for r in data.get("results", []):
        if r.get("issue_severity") == "LOW" and r.get("issue_confidence") == "LOW":
            continue
        rel = Path(os.path.relpath(r["filename"], root)).as_posix()
        if r.get("test_id") == "B101":  # assert usage: noise
            continue
        severity = sev.get(r.get("issue_severity"), "low")
        if "test" in rel.lower():
            severity = SEVERITY_DOWNGRADE[severity]
        out.append(Finding(
            f"bandit-{r.get('test_id')}", r.get("test_name", "bandit issue").replace("_", " ").capitalize(),
            "security", severity, rel, int(r.get("line_number", 1)),
            r.get("issue_text", ""), f"See Bandit docs: {r.get('more_info', '')}",
            snippet=(r.get("code") or "").strip().splitlines()[0][:300] if r.get("code") else "",
            source="bandit", confidence=str(r.get("issue_confidence", "MEDIUM")).lower(),
            cwe=f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else None))
    return out, f"ran ({len(out)} findings)"


def run_semgrep(root: str) -> tuple[list[Finding], str]:
    if os.getenv("CODEGUARD_SEMGREP", "1") == "0":
        return [], "disabled (CODEGUARD_SEMGREP=0)"
    exe = shutil.which("semgrep")
    if not exe:
        return [], "skipped (semgrep not installed)"
    cmd = [exe, "scan", "--config", os.getenv("CODEGUARD_SEMGREP_CONFIG", "p/default"), "--json",
           "--quiet", "--metrics", "off", "--timeout", "30", root]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        return [], f"failed ({exc.__class__.__name__})"
    sev = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    out = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        cwe = meta.get("cwe")
        out.append(Finding(
            f"semgrep-{r.get('check_id', '').split('.')[-1]}", r.get("check_id", "semgrep").split(".")[-1].replace("-", " ").capitalize(),
            "security", sev.get(extra.get("severity"), "medium"),
            Path(os.path.relpath(r.get("path", ""), root)).as_posix(), int(r.get("start", {}).get("line", 1)),
            extra.get("message", ""), "See the Semgrep rule documentation for remediation guidance.",
            snippet=(extra.get("lines") or "").strip()[:300], source="semgrep",
            cwe=(cwe[0] if isinstance(cwe, list) and cwe else cwe if isinstance(cwe, str) else None)))
    return out, f"ran ({len(out)} findings)"


def scan_security(files: list[SourceFile]) -> list[Finding]:
    return run_line_rules(SECURITY_RULES, files) + python_ast_security(files) + project_security_checks(files)
