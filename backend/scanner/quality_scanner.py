"""Quality scanning: AI slop, coding gaps and loose ends.

* Python files get a real AST pass (empty functions, swallowed exceptions,
  unused imports, duplicated bodies, mutable defaults, missing timeouts...).
* Every other language gets regex/structural checks so the agent stays
  architecture- and language-agnostic.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

from .file_scanner import SourceFile
from .models import Finding
from .rules import SUPPRESS_MARKER, Rule, run_line_rules, run_multiline_rules

I = re.IGNORECASE
JS = {"javascript", "typescript", "vue", "svelte"}
C_LIKE = JS | {"java", "kotlin", "scala", "csharp", "go", "php", "c", "cpp", "rust", "swift", "dart"}

# ---------------------------------------------------------------- line rules
QUALITY_RULES: list[Rule] = [
    # ----- loose ends
    Rule("todo-comment", "TODO left in code", "loose_end", "low",
         re.compile(r"(?:#|//|/\*|\*|--|<!--)\s*(?P<tag>TODO|FIXME|HACK|XXX|BUG)\b[:\s-]*(?P<text>.*)"),
         "Unfinished work marker. These tend to accumulate and hide known problems from reviewers.",
         "Resolve it now, or move it to your issue tracker and reference the ticket ID.",
         kinds=("code", "config"), skip_comments=False,
         title_from_match=lambda m: f"{m.group('tag')}: {m.group('text').strip()[:80] or '(no description)'}",
         severity_from_match=lambda m: "low" if m.group("tag") == "TODO" else "medium"),
    Rule("not-implemented", "Unimplemented code path", "gap", "medium",
         re.compile(r"throw\s+new\s+(?:UnsupportedOperationException|NotImplementedException|NotImplementedError)\s*\(|"
                    r"throw\s+new\s+Error\(\s*['\"`](?:not\s+implemented|todo|unimplemented)|"
                    r"\b(?:todo|unimplemented)!\s*\(|panic\(\s*\"(?:not implemented|todo|unimplemented)|\bTODO\(\s*\"", I),
         "This code path deliberately fails at runtime because it was never implemented.",
         "Implement the behaviour, or remove the code path and its callers.", languages=C_LIKE),
    Rule("hardcoded-localhost", "Hardcoded localhost URL", "loose_end", "low",
         re.compile(r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?"),
         "A development URL is hardcoded and will break (or silently point to the wrong place) in other environments.",
         "Read the base URL from configuration / environment variables.", skip_tests=True),
    Rule("simulated-logic", "Simulated / mocked logic in production code", "loose_end", "medium",
         re.compile(r"\b(?:simulat(?:e|ed|ing)|mock(?:ed)?|fake|dummy|hardcoded)\s+(?:the\s+)?(?:api|response|data|payment|auth\w*|login|database|db|call|result|user)s?\b", I),
         "Comment/code indicates logic is faked or simulated. A common AI-generated shortcut that ships to production unnoticed.",
         "Replace the simulation with the real implementation, or clearly isolate it behind a feature flag / test double.",
         kinds=("code",), skip_comments=False, skip_tests=True),

    # ----- AI slop
    Rule("ai-slop-marker", "AI-generated placeholder text", "slop", "medium",
         re.compile(r"as an ai (?:language )?model|rest of (?:the |your )?(?:code|implementation|file|logic)\s+(?:remains|stays|is)|"
                    r"\.\.\.\s*(?:existing|rest of|other|remaining) (?:code|logic|implementation|methods)|"
                    r"(?:add|insert|implement|put|write) (?:your )?(?:own )?(?:code|logic|implementation) here|"
                    r"implementation (?:goes|left) here|here(?:'s| is) (?:the|an?) (?:updated|complete|corrected|modified|full) (?:code|version|implementation)|"
                    r"i hope this helps|let me know if you (?:need|have|want)|for (?:demo(?:nstration)?|illustration|example) purposes only", I),  # codeguard: ignore (rule definition)
         "Text that is typical of copy-pasted LLM output: the surrounding code is likely incomplete or unreviewed.",
         "Review this section line by line, finish the missing parts and delete the conversational text.",
         kinds=("code", "config"), skip_comments=False, confidence="high"),
    Rule("in-real-app", "\"In a real application...\" shortcut", "slop", "medium",  # codeguard: ignore (rule definition)
         re.compile(r"in a (?:real|production)(?:[- ]world)? (?:app(?:lication)?|implementation|scenario|system|project|environment)|"
                    r"(?:should|would) be (?:replaced|implemented|handled) (?:in|for) production", I),
         "The author admits this code is not production-ready (classic AI-generated scaffolding).",
         "Implement the production behaviour described in the comment before shipping.",
         skip_comments=False, skip_tests=True, confidence="high"),
    Rule("debug-leftover", "Debug statement left in code", "slop", "low",
         re.compile(r"\bconsole\.(?:log|debug|trace)\s*\(|\bSystem\.out\.print(?:ln)?\s*\(|\.printStackTrace\s*\(\s*\)|"
                    r"\bvar_dump\s*\(|\bprint_r\s*\(|\bdd\s*\("),
         "Debug output left behind clutters logs and can leak internal data.",
         "Remove it or replace it with a proper logger at the right level.",
         languages=C_LIKE, skip_tests=True),
    Rule("debugger-breakpoint", "Debugger breakpoint left in code", "slop", "medium",
         re.compile(r"\bdebugger\s*;|\bpdb\.set_trace\s*\(|(?<![\w.])breakpoint\s*\(\s*\)|\bbinding\.pry\b|\bbyebug\b"),
         "A breakpoint will halt or slow down the application when this line runs.",
         "Remove the breakpoint before committing."),
    Rule("suppressed-checks", "Type checks / linter suppressed", "slop", "low",
         re.compile(r"@ts-ignore|@ts-nocheck|eslint-disable(?!-next-line)|#\s*type:\s*ignore(?!\[)|#\s*noqa(?!:)|"  # codeguard: ignore (rule definition)
                    r"@SuppressWarnings\(\s*\"all\"\s*\)|//\s*nolint\b|#\s*pylint:\s*disable=all"),
         "A blanket suppression hides real problems from the tools meant to catch them.",
         "Fix the underlying warning, or suppress only the specific rule with a justification.",
         skip_comments=False),
    Rule("typescript-any", "Type safety bypassed with `any`", "slop", "low",
         re.compile(r":\s*any\b(?!\w)|\bas\s+any\b|<any>"),
         "`any` disables type checking for this value, which defeats the point of TypeScript.",
         "Give the value a precise type, or use `unknown` and narrow it.", languages={"typescript"}),
]

MULTILINE_RULES: list[Rule] = [
    Rule("empty-catch", "Empty catch block (error silently swallowed)", "gap", "medium",
         re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}|\.catch\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*\{\s*\}\s*\)|"
                    r"\.catch\(\s*\(\s*\)\s*=>\s*(?:null|undefined)\s*\)"),
         "Errors are caught and ignored. Failures become invisible and leave the system in an inconsistent state.",
         "Log the error with context, handle it, or let it propagate. Never ignore it silently.",
         languages=C_LIKE),
    Rule("go-ignored-error", "Go error checked but not handled", "gap", "medium",
         re.compile(r"if\s+err\s*!=\s*nil\s*\{\s*\}"),
         "The error branch is empty, so the failure is silently ignored.",
         "Return, wrap or log the error.", languages={"go"}),
    Rule("empty-function", "Empty function / method", "gap", "medium",
         re.compile(r"\bfunction\s+(?P<name>\w+)\s*\([^)]*\)\s*\{\s*\}|"
                    r"\b(?:public|private|protected|internal)\s+(?:static\s+)?(?:async\s+)?[\w<>\[\],]+\s+(?P<jname>\w+)\s*\([^)]*\)\s*(?:throws\s+[\w., ]+)?\{\s*\}|"
                    r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<gname>\w+)\s*\([^)]*\)\s*(?:\w+\s*)?\{\s*\}"),
         "The function has no body. Callers believe work is being done when nothing happens.",
         "Implement the function, or remove it (and its callers) if it is not needed.",
         languages=C_LIKE,
         title_from_match=lambda m: f"Empty function: {m.group('name') or m.group('jname') or m.group('gname')}()"),
]


# ---------------------------------------------------------------- Python AST
def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


def _is_noop(stmt: ast.stmt) -> bool:
    return isinstance(stmt, (ast.Pass, ast.Continue)) or (
        isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and stmt.value.value is Ellipsis)


def _decorator_names(node) -> set[str]:
    names = set()
    for d in node.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute):
            names.add(target.attr)
        elif isinstance(target, ast.Name):
            names.add(target.id)
    return names


def _raises_not_implemented(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Raise) or stmt.exc is None:
        return False
    exc = stmt.exc.func if isinstance(stmt.exc, ast.Call) else stmt.exc
    return isinstance(exc, ast.Name) and exc.id == "NotImplementedError"


HTTP_LIBS = {"requests", "httpx"}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "request"}


class _PyQualityVisitor(ast.NodeVisitor):
    def __init__(self, f: SourceFile):
        self.f = f
        self.findings: list[Finding] = []
        self.class_stack: list[ast.ClassDef] = []
        self.bodies: list[tuple[str, int, str, str]] = []  # (hash, line, func name, file)

    def add(self, rule_id, title, category, severity, line, desc, reco, confidence="high"):
        if SUPPRESS_MARKER.search(self.f.line(line)):
            return
        self.findings.append(Finding(rule_id, title, category, severity, self.f.path, line, desc, reco,
                                     snippet=self.f.line(line).strip()[:300], source="ast", confidence=confidence))

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_stack.append(node)
        self.generic_visit(node)
        self.class_stack.pop()

    def _in_interface(self) -> bool:
        if not self.class_stack:
            return False
        bases = {getattr(b, "id", getattr(b, "attr", "")) for b in self.class_stack[-1].bases}
        return bool(bases & {"Protocol", "ABC", "Interface"})

    def _function(self, node):
        decorators = _decorator_names(node)
        abstract = bool(decorators & {"abstractmethod", "overload", "abstractproperty"}) or self._in_interface()
        body = _strip_docstring(node.body)

        if not abstract:
            if not body or all(_is_noop(s) for s in body):
                self.add("empty-function", f"Empty function: {node.name}()", "gap", "medium", node.lineno,
                         "The function body is only `pass`/`...`. Callers believe work is done when nothing happens.",
                         "Implement the function, or delete it and its callers if it is not needed.")
            elif len(body) <= 2 and any(_raises_not_implemented(s) for s in body):
                self.add("not-implemented", f"Unimplemented function: {node.name}()", "gap", "medium", node.lineno,
                         "The function only raises NotImplementedError, so any call fails at runtime.",
                         "Implement the function, or mark the class abstract with @abstractmethod.")

        length = (node.end_lineno or node.lineno) - node.lineno + 1
        if length > 80:
            self.add("long-function", f"Overly long function: {node.name}() ({length} lines)", "slop", "low",
                     node.lineno, "Very long functions are hard to review and test, and are a common smell of generated code.",
                     "Split it into smaller, well-named helpers with a single responsibility.", "medium")
        n_args = len(node.args.args) + len(node.args.kwonlyargs)
        if n_args > 7:
            self.add("too-many-params", f"Too many parameters: {node.name}() takes {n_args}", "slop", "low",
                     node.lineno, "Long parameter lists are error-prone and hint at a missing abstraction.",
                     "Group related parameters into a dataclass / config object.", "medium")
        for default in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                    isinstance(default, ast.Call) and getattr(default.func, "id", "") in {"list", "dict", "set"}):
                self.add("mutable-default", f"Mutable default argument in {node.name}()", "gap", "medium",
                         default.lineno, "Default lists/dicts are shared across calls, so state leaks between invocations.",
                         "Use `None` as the default and create the object inside the function.")
                break

        if len(body) >= 4:
            dump = ast.dump(ast.Module(body=body, type_ignores=[]))
            self.bodies.append((hashlib.blake2b(dump.encode(), digest_size=8).hexdigest(), node.lineno, node.name, self.f.path))
        self.generic_visit(node)

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        broad = node.type is None or getattr(node.type, "id", "") in {"Exception", "BaseException"}
        skip_item = len(node.body) == 1 and isinstance(node.body[0], ast.Continue) and not broad
        if node.body and all(_is_noop(s) for s in node.body) and not skip_item:
            self.add("swallowed-exception", "Exception silently swallowed (except: pass)", "gap",
                     "high" if broad else "medium", node.lineno,
                     "The error is caught and discarded. Failures become invisible and data can end up half-written.",
                     "Log the exception with context and handle it, or let it propagate.")
        elif node.type is None:
            self.add("bare-except", "Bare `except:` clause", "gap", "medium", node.lineno,
                     "A bare except also catches KeyboardInterrupt/SystemExit and hides programming errors.",
                     "Catch the specific exceptions you expect (e.g. `except ValueError:`).")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and \
                func.value.id in HTTP_LIBS and func.attr in HTTP_METHODS:
            if not any(k.arg == "timeout" for k in node.keywords) and not any(k.arg is None for k in node.keywords):
                self.add("missing-timeout", f"HTTP call without timeout: {func.value.id}.{func.attr}()", "gap", "low",
                         node.lineno, "Without a timeout a slow or dead upstream can hang this worker forever.",
                         "Always pass an explicit timeout, e.g. requests.get(url, timeout=10).")
        self.generic_visit(node)


def _unused_imports(f: SourceFile, tree: ast.Module) -> list[Finding]:
    if Path(f.path).name == "__init__.py":
        return []
    imported: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for a in node.names:
                if a.name != "*":
                    imported[a.asname or a.name] = node.lineno
    if not imported:
        return []
    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Attribute):
            base = node
            while isinstance(base, ast.Attribute):
                base = base.value
            if isinstance(base, ast.Name):
                used.add(base.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 200:
            used.update(re.findall(r"[A-Za-z_]\w*", node.value))  # __all__ and string annotations
    out = []
    for name, line in imported.items():
        if name not in used and not SUPPRESS_MARKER.search(f.line(line)):
            out.append(Finding("unused-import", f"Unused import: {name}", "slop", "low", f.path, line,
                               "Imported but never used: dead weight that often appears in generated code.",
                               "Remove the import.", snippet=f.line(line).strip(), source="ast", confidence="high"))
    return out[:10]


def python_ast_quality(files: list[SourceFile]) -> list[Finding]:
    findings: list[Finding] = []
    bodies: list[tuple[str, int, str, str]] = []
    for f in files:
        if f.language != "python":
            continue
        try:
            tree = ast.parse(f.text)
        except SyntaxError as exc:
            findings.append(Finding("syntax-error", "File does not parse (syntax error)", "gap", "high", f.path,
                                    exc.lineno or 1, f"Python could not parse this file: {exc.msg}.",
                                    "Fix the syntax error. Broken files are a strong sign of unreviewed / truncated generated code.",
                                    snippet=f.line(exc.lineno or 1).strip(), source="ast", confidence="high"))
            continue
        except ValueError:
            continue
        v = _PyQualityVisitor(f)
        v.visit(tree)
        findings.extend(v.findings)
        findings.extend(_unused_imports(f, tree))
        bodies.extend(v.bodies)

    groups: dict[str, list] = defaultdict(list)
    for h, line, name, path in bodies:
        groups[h].append((path, line, name))
    for occurrences in groups.values():
        if len(occurrences) < 2:
            continue
        first = occurrences[0]
        for path, line, name in occurrences[1:]:
            findings.append(Finding(
                "duplicate-code", f"Duplicated logic: {name}() is identical to {first[2]}()", "slop", "medium",
                path, line, f"This function body is an exact copy of {first[2]}() in {first[0]}:{first[1]}. "
                "Copy-pasted logic drifts apart and doubles the bug surface.",
                "Extract the shared logic into one function and call it from both places.",
                source="ast", confidence="high"))
    return findings


# ---------------------------------------------------------------- non-Python duplicate blocks
_TRIVIAL = re.compile(r"^(?:[{}()\[\];,]*|import\b.*|from\b.*|#include\b.*|using\b.*|package\b.*|//.*|#.*|\*.*|/\*.*|\}\s*else\s*\{|return;?|break;?)$")
WINDOW = 6


def duplicate_blocks(files: list[SourceFile]) -> list[Finding]:
    seen: dict[str, tuple[str, int]] = {}
    out: list[Finding] = []
    for f in files:
        if f.kind != "code" or f.language in {"python", "html", "sql"} or f.is_test:
            continue
        norm = [(i + 1, " ".join(l.split())) for i, l in enumerate(f.lines)]
        norm = [(n, l) for n, l in norm if len(l) > 3 and not _TRIVIAL.match(l)]
        i = 0
        while i <= len(norm) - WINDOW:
            chunk = "\n".join(l for _, l in norm[i:i + WINDOW])
            h = hashlib.blake2b(chunk.encode(), digest_size=8).hexdigest()
            line = norm[i][0]
            prev = seen.get(h)
            if prev and prev != (f.path, line):
                out.append(Finding(
                    "duplicate-code", f"Duplicated block (also in {prev[0]}:{prev[1]})", "slop", "medium",
                    f.path, line, f"{WINDOW}+ lines here are identical to {prev[0]}:{prev[1]}. Copy-paste duplication.",
                    "Extract the shared logic into a reusable function/module.", snippet=norm[i][1][:300],
                    confidence="medium"))
                i += WINDOW
                if len(out) >= 30:
                    return out
                continue
            seen.setdefault(h, (f.path, line))
            i += 1
    return out


# ---------------------------------------------------------------- project-level checks
def project_quality_checks(files: list[SourceFile], profile: dict) -> list[Finding]:
    out: list[Finding] = []
    if profile.get("code_files", 0) >= 3 and profile.get("test_files", 0) == 0:
        out.append(Finding("no-tests", "No automated tests found", "gap", "medium", "(project)", 0,
                           "The project has source code but no test files, so regressions and security fixes can't be verified.",
                           "Add unit tests for the critical paths (auth, payments, data access) and run them in CI.",
                           confidence="high"))
    if profile.get("code_files", 0) >= 1 and not profile.get("has_readme"):
        out.append(Finding("no-readme", "No README at project root", "loose_end", "low", "(project)", 0,
                           "Nobody can set up, run or review the project without documentation.",
                           "Add a README with purpose, setup steps, configuration and how to run tests."))

    for f in files:
        name = Path(f.path).name
        if f.language == "requirements":
            unpinned = [l.strip() for l in f.lines
                        if l.strip() and not l.strip().startswith(("#", "-")) and not re.search(r"==|~=|===|@", l)]
            if unpinned:
                out.append(Finding("unpinned-dependencies", f"{len(unpinned)} unpinned Python dependencies", "loose_end", "low",
                                   f.path, 1, "Unpinned dependencies make builds non-reproducible and can silently pull in "
                                   "breaking or compromised versions.",
                                   "Pin exact versions (pip freeze / pip-tools / uv lock).",
                                   snippet=", ".join(unpinned[:6])[:300], confidence="high"))
        elif name == "package.json":
            try:
                pkg = json.loads(f.text)
            except ValueError:
                continue
            deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})}
            loose = [k for k, v in deps.items() if isinstance(v, str) and v.strip() in {"*", "latest", "", "x"}]
            if loose:
                out.append(Finding("unpinned-dependencies", f"{len(loose)} npm dependencies use '*' or 'latest'", "loose_end", "medium",
                                   f.path, 1, "Wildcard versions can install any future release, including malicious or breaking ones.",
                                   "Use explicit semver ranges and commit a lockfile.", snippet=", ".join(loose[:6]),
                                   confidence="high"))
    return out


def scan_quality(files: list[SourceFile], profile: dict) -> list[Finding]:
    return (
        run_line_rules(QUALITY_RULES, files)
        + run_multiline_rules(MULTILINE_RULES, files)
        + python_ast_quality(files)
        + duplicate_blocks(files)
        + project_quality_checks(files, profile)
    )
