from __future__ import annotations

import ast
import hashlib

from .discovery_models import DiscoveredCall, DiscoveryGap, DiscoveryResult


ADAPTER_VERSION = "python-openai-responses-static-1"


def _chain(node: ast.expr) -> tuple[str, ...]:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return tuple(reversed(parts))


def _handler_names(node: ast.Try) -> set[str]:
    names: set[str] = set()
    for handler in node.handlers:
        if handler.type is not None:
            for candidate in ast.walk(handler.type):
                if isinstance(candidate, (ast.Attribute, ast.Name)):
                    names.update(_chain(candidate))
    return names


def _is_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _keyword_names(node: ast.Call) -> set[str]:
    return {keyword.arg for keyword in node.keywords if keyword.arg is not None}


def _call_digest(node: ast.Call) -> str:
    normalized = ast.dump(node, annotate_fields=True, include_attributes=False)
    return f"sha256:{hashlib.sha256(normalized.encode()).hexdigest()}"


class _FunctionLocals(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.external: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_Global(self, node: ast.Global) -> None:
        self.external.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.external.update(node.names)


def _function_locals(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    visitor = _FunctionLocals()
    arguments = (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
    visitor.names.update(argument.arg for argument in arguments)
    if node.args.vararg is not None:
        visitor.names.add(node.args.vararg.arg)
    if node.args.kwarg is not None:
        visitor.names.add(node.args.kwarg.arg)
    for statement in node.body:
        visitor.visit(statement)
    return visitor.names - visitor.external


class _Discovery(ast.NodeVisitor):
    def __init__(self) -> None:
        self.openai_constructors: set[str] = set()
        self.openai_modules: set[str] = set()
        self.clients: dict[str, set[str]] = {}
        self.resources: dict[str, tuple[str, set[str]]] = {}
        self.calls: list[DiscoveredCall] = []
        self.gaps: list[DiscoveryGap] = []
        self.symbols: list[str] = ["module"]
        self.tries: list[set[str]] = []
        self.wrapper_depth = 0
        self.imported_anthropic = False

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "openai":
                self.openai_modules.add(alias.asname or "openai")
            elif alias.name.startswith("anthropic"):
                self.imported_anthropic = True

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "openai":
            for alias in node.names:
                if alias.name in {"OpenAI", "AsyncOpenAI"}:
                    self.openai_constructors.add(alias.asname or alias.name)
        elif node.module is not None and node.module.startswith("anthropic"):
            self.imported_anthropic = True

    def _constructor_features(self, node: ast.Call) -> set[str] | None:
        chain = _chain(node.func)
        is_constructor = (
            len(chain) == 1 and chain[0] in self.openai_constructors
        ) or (
            len(chain) == 2 and chain[0] in self.openai_modules and chain[1] in {"OpenAI", "AsyncOpenAI"}
        )
        if not is_constructor:
            return None
        features: set[str] = set()
        if chain[-1] == "AsyncOpenAI":
            features.add("asynchronous")
        if "max_retries" in _keyword_names(node):
            features.add("retries_configured")
        return features

    def _binding(self, value: ast.expr) -> tuple[str, set[str]] | None:
        if isinstance(value, ast.Call):
            features = self._constructor_features(value)
            if features is not None:
                return "client", features
        if isinstance(value, ast.Name):
            if value.id in self.clients:
                return "client", set(self.clients[value.id])
            if value.id in self.resources:
                operation, features = self.resources[value.id]
                return operation, set(features)
        chain = _chain(value)
        if len(chain) == 2 and chain[0] in self.clients and chain[1] == "responses":
            return "responses", set(self.clients[chain[0]]) | {"resource_alias"}
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        binding = self._binding(node.value)
        if binding is None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.clients.pop(target.id, None)
                    self.resources.pop(target.id, None)
            return
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            kind, features = binding
            if kind == "client":
                self.clients[target.id] = features | ({"client_alias"} if isinstance(node.value, ast.Name) else set())
            elif kind == "responses":
                self.resources[target.id] = (kind, features)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None or not isinstance(node.target, ast.Name):
            if isinstance(node.target, ast.Name):
                self.clients.pop(node.target.id, None)
                self.resources.pop(node.target.id, None)
            return
        self.visit(node.value)
        binding = self._binding(node.value)
        if binding is None:
            return
        kind, features = binding
        if kind == "client":
            self.clients[node.target.id] = features | ({"client_alias"} if isinstance(node.value, ast.Name) else set())
        elif kind == "responses":
            self.resources[node.target.id] = (kind, features)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        saved = (
            self.clients,
            self.resources,
            self.openai_constructors,
            self.openai_modules,
        )
        self.clients = self.clients.copy()
        self.resources = self.resources.copy()
        self.openai_constructors = self.openai_constructors.copy()
        self.openai_modules = self.openai_modules.copy()
        for name in _function_locals(node):
            self.clients.pop(name, None)
            self.resources.pop(name, None)
            self.openai_constructors.discard(name)
            self.openai_modules.discard(name)
        self.symbols.append(node.name)
        self.wrapper_depth += 1
        for statement in node.body:
            self.visit(statement)
        self.wrapper_depth -= 1
        self.symbols.pop()
        self.clients, self.resources, self.openai_constructors, self.openai_modules = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        if isinstance(node.target, ast.Name):
            self.clients.pop(node.target.id, None)
            self.resources.pop(node.target.id, None)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.symbols.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.symbols.pop()

    def visit_Try(self, node: ast.Try) -> None:
        self.tries.append(_handler_names(node))
        for statement in node.body:
            self.visit(statement)
        self.tries.pop()
        for handler in node.handlers:
            for statement in handler.body:
                self.visit(statement)
        for statement in (*node.orelse, *node.finalbody):
            self.visit(statement)

    def _resolved_call(self, node: ast.Call) -> tuple[str, set[str]] | None:
        chain = _chain(node.func)
        if len(chain) >= 3 and chain[-2] == "responses" and chain[-1] in {"create", "parse"}:
            root = chain[0]
            if root in self.clients or root in self.openai_modules:
                features = set(self.clients.get(root, set()))
                return f"responses.{chain[-1]}", features
            return None
        if len(chain) == 2 and chain[0] in self.resources and chain[1] in {"create", "parse"}:
            _, features = self.resources[chain[0]]
            return f"responses.{chain[1]}", set(features)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"create", "parse"}:
            value = node.func.value
            if isinstance(value, ast.Attribute) and value.attr == "responses" and isinstance(value.value, ast.Call):
                constructor_features = self._constructor_features(value.value)
                if constructor_features is not None:
                    return f"responses.{node.func.attr}", constructor_features
                options_chain = _chain(value.value.func)
                if len(options_chain) == 2 and options_chain[0] in self.clients and options_chain[1] == "with_options":
                    features = set(self.clients[options_chain[0]])
                    if "max_retries" in _keyword_names(value.value):
                        features.add("retries_configured")
                    return f"responses.{node.func.attr}", features
        return None

    def _is_dynamic_response_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"create", "parse"}:
            value = node.func.value
            if isinstance(value, ast.Call):
                chain = _chain(value.func)
                if chain == ("getattr",) and len(value.args) >= 2:
                    member = value.args[1]
                    return isinstance(member, ast.Constant) and member.value == "responses"
                return bool(self.openai_constructors or self.openai_modules) and (
                    isinstance(value.func, ast.Name) and value.func.id not in self.openai_constructors
                )
            if isinstance(value, ast.Subscript):
                return bool(self.openai_constructors or self.openai_modules)
            chain = _chain(value)
            return bool(self.openai_constructors or self.openai_modules) and bool(chain and chain[-1] == "responses")
        return False

    def visit_Call(self, node: ast.Call) -> None:
        chain = _chain(node.func)
        if chain[-3:] == ("chat", "completions", "create"):
            self.gaps.append(
                DiscoveryGap("unsupported_operation", "L0", "Migrate or separately adapt this Chat Completions callsite.")
            )
        elif chain[-2:] == ("ChatCompletion", "create"):
            self.gaps.append(
                DiscoveryGap("unsupported_sdk_version", "L0", "Migrate the legacy OpenAI SDK surface before analysis.")
            )
        else:
            resolved = self._resolved_call(node)
            if resolved is not None:
                operation, features = resolved
                names = _keyword_names(node)
                parent = getattr(node, "_promptectomy_parent", None)
                if isinstance(parent, ast.Await) or "asynchronous" in features:
                    features.discard("synchronous")
                    features.add("asynchronous")
                else:
                    features.add("synchronous")
                stream_keyword = next((item.value for item in node.keywords if item.arg == "stream"), None)
                if stream_keyword is not None and _is_true(stream_keyword):
                    features.add("streaming")
                if "tools" in names:
                    features.add("tools")
                if operation == "responses.parse" or names.intersection({"text", "response_format"}):
                    features.add("structured_output")
                if names.intersection({"max_retries", "retry"}):
                    features.add("retries_configured")
                handler_names = set().union(*self.tries) if self.tries else set()
                if handler_names.intersection({"APIError", "APIConnectionError", "APITimeoutError", "RateLimitError", "OpenAIError"}):
                    features.add("errors_handled")
                if handler_names.intersection({"CancelledError", "asyncio"}):
                    features.add("cancellation_handled")
                if names.intersection({"timeout", "signal"}):
                    features.add("cancellation_bounded")
                if self.wrapper_depth:
                    features.add("wrapper_body")
                enclosing_symbol = ".".join(self.symbols)
                normalized_digest = _call_digest(node)
                ordinal = sum(
                    item.enclosing_symbol == enclosing_symbol
                    and item.operation == operation
                    and item.normalized_ast_digest == normalized_digest
                    for item in self.calls
                )
                self.calls.append(
                    DiscoveredCall(
                        line=node.lineno,
                        language="python",
                        operation=operation,
                        normalized_ast_digest=normalized_digest,
                        enclosing_symbol=enclosing_symbol,
                        features=tuple(sorted(features)),
                        ast_ordinal=ordinal,
                    )
                )
            elif self._is_dynamic_response_call(node):
                self.gaps.append(
                    DiscoveryGap(
                        "ambiguous_dynamic_callsite",
                        "L0",
                        "Replace dynamic Responses dispatch with a statically bindable callsite or declare a reviewed wrapper.",
                    )
                )
        self.generic_visit(node)


def discover_python(source: bytes) -> DiscoveryResult:
    try:
        text = source.decode("utf-8")
        tree = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError("malformed_source") from exc
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            setattr(child, "_promptectomy_parent", parent)
    discovery = _Discovery()
    discovery.visit(tree)
    if discovery.imported_anthropic:
        discovery.gaps.append(
            DiscoveryGap("unsupported_provider", "L0", "Use the OpenAI Responses adapter or add a reviewed provider adapter.")
        )
    return DiscoveryResult(tuple(discovery.calls), tuple(discovery.gaps))
