from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .discovery_models import DiscoveredCall, DiscoveryGap, DiscoveryResult, Language


ADAPTER_VERSION = "typescript-openai-responses-tree-sitter-1"
_SCOPE_TYPES = {
    "program",
    "function_declaration",
    "function_expression",
    "arrow_function",
    "generator_function_declaration",
    "generator_function",
    "method_definition",
}


@dataclass(frozen=True)
class _Binding:
    kind: str
    features: frozenset[str] = frozenset()


def _text(source: bytes, node: Any) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8")


def _walk(node: Any):
    yield node
    for child in node.children:
        yield from _walk(child)


def _scope(node: Any) -> Any:
    current = node
    while current.parent is not None and current.type not in _SCOPE_TYPES:
        current = current.parent
    return current


def _scope_key(node: Any) -> tuple[str, int, int]:
    return node.type, node.start_byte, node.end_byte


def _scope_chain(node: Any):
    current = _scope(node)
    while current is not None:
        if current.type in _SCOPE_TYPES:
            yield current
        current = current.parent


def _member_chain(source: bytes, node: Any) -> tuple[str, ...] | None:
    if node.type in {"identifier", "property_identifier"}:
        return (_text(source, node),)
    if node.type != "member_expression":
        return None
    object_node = node.child_by_field_name("object")
    property_node = node.child_by_field_name("property")
    if object_node is None or property_node is None:
        return None
    punctuation = [child.type for child in node.children if not child.is_named]
    if "." not in punctuation or "[" in punctuation or "?." in punctuation:
        return None
    prefix = _member_chain(source, object_node)
    if prefix is None or property_node.type not in {"identifier", "property_identifier"}:
        return None
    return (*prefix, _text(source, property_node))


def _pair_keys(source: bytes, node: Any) -> dict[str, Any]:
    pairs: dict[str, Any] = {}
    for candidate in _walk(node):
        if candidate.type == "pair":
            key = candidate.child_by_field_name("key")
            value = candidate.child_by_field_name("value")
            if key is not None and value is not None and key.type in {"identifier", "property_identifier", "string"}:
                pairs[_text(source, key).strip("'\"")] = value
        elif candidate.type == "shorthand_property_identifier":
            pairs[_text(source, candidate)] = candidate
    return pairs


def _normalized_digest(source: bytes, node: Any) -> str:
    parts: list[bytes] = []
    for candidate in _walk(node):
        if not candidate.is_named:
            continue
        parts.append(candidate.type.encode())
        if candidate.child_count == 0:
            parts.append(source[candidate.start_byte : candidate.end_byte])
    return f"sha256:{hashlib.sha256(b'\0'.join(parts)).hexdigest()}"


def _enclosing_symbol(source: bytes, node: Any) -> tuple[str, bool]:
    for candidate in _scope_chain(node):
        if candidate.type == "program":
            break
        name = candidate.child_by_field_name("name")
        if name is not None:
            return _text(source, name), True
        parent = candidate.parent
        if parent is not None and parent.type == "variable_declarator":
            variable = parent.child_by_field_name("name")
            if variable is not None and variable.type == "identifier":
                return _text(source, variable), True
        return "anonymous", True
    return "module", False


def _has_catch(source: bytes, node: Any) -> bool:
    current = node.parent
    while current is not None:
        if current.type == "try_statement":
            body = current.child_by_field_name("body")
            handler = current.child_by_field_name("handler")
            if body is not None and handler is not None and body.start_byte <= node.start_byte < body.end_byte:
                return True
        current = current.parent
    call = node
    while call.parent is not None and call.parent.type in {"await_expression", "member_expression", "call_expression"}:
        call = call.parent
        if call.type == "member_expression":
            property_node = call.child_by_field_name("property")
            if property_node is not None and property_node.type in {"identifier", "property_identifier"}:
                if _text(source, property_node) == "catch":
                    return True
    return False


def _load_parser(relative: str):
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_typescript
        language_capsule = (
            tree_sitter_typescript.language_tsx()
            if relative.endswith((".tsx", ".jsx"))
            else tree_sitter_typescript.language_typescript()
        )
        return Parser(Language(language_capsule))
    except (ModuleNotFoundError, ImportError, AttributeError, TypeError):
        return None


def discover_javascript(source: bytes, language: Language, *, relative: str = "source.ts") -> DiscoveryResult:
    try:
        source.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("malformed_source") from exc
    parser = _load_parser(relative)
    if parser is None:
        return DiscoveryResult(
            (),
            (
                DiscoveryGap(
                    "unsupported_toolchain",
                    "L0",
                    "Install the pinned Tree-sitter TypeScript adapter before running stable discovery.",
                ),
            ),
        )
    tree = parser.parse(source)
    if tree.root_node.has_error:
        raise ValueError("malformed_source")

    constructors: set[str] = set()
    modules: set[str] = set()
    anthropic = False
    constructor_declarations: list[tuple[Any, str]] = []
    declared: dict[tuple[str, int, int], set[str]] = {}
    bindings: dict[tuple[tuple[str, int, int], str], _Binding] = {}

    for node in _walk(tree.root_node):
        if node.type != "import_statement":
            continue
        source_node = node.child_by_field_name("source")
        module = _text(source, source_node).strip("'\"") if source_node is not None else ""
        if module in {"anthropic", "@anthropic-ai/sdk"}:
            anthropic = True
        if module != "openai":
            continue
        clause = next((child for child in node.named_children if child.type == "import_clause"), None)
        if clause is None:
            continue
        for child in clause.named_children:
            if child.type == "identifier":
                constructors.add(_text(source, child))
            elif child.type == "named_imports":
                for specifier in child.named_children:
                    name = specifier.child_by_field_name("name")
                    alias = specifier.child_by_field_name("alias")
                    if name is not None and _text(source, name) in {"OpenAI", "AsyncOpenAI"}:
                        constructors.add(_text(source, alias or name))
            elif child.type == "namespace_import":
                identifiers = [item for item in child.named_children if item.type == "identifier"]
                if identifiers:
                    modules.add(_text(source, identifiers[-1]))

    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None or function.type != "identifier" or _text(source, function) != "require":
            continue
        strings = [item for item in arguments.named_children if item.type == "string"]
        module = _text(source, strings[0]).strip("'\"") if strings else ""
        if module in {"anthropic", "@anthropic-ai/sdk"}:
            anthropic = True
        if module != "openai" or node.parent is None or node.parent.type != "variable_declarator":
            continue
        name = node.parent.child_by_field_name("name")
        if name is not None and name.type == "identifier":
            constructor_declarations.append((node.parent, _text(source, name)))

    declarators = [node for node in _walk(tree.root_node) if node.type == "variable_declarator"]
    for node in declarators:
        name_node = node.child_by_field_name("name")
        if name_node is not None and name_node.type == "identifier":
            declared.setdefault(_scope_key(_scope(node)), set()).add(_text(source, name_node))
    for node, name in constructor_declarations:
        bindings[(_scope_key(_scope(node)), name)] = _Binding("constructor")

    def lookup(node: Any, name: str) -> _Binding | None:
        for candidate_scope in _scope_chain(node):
            key = _scope_key(candidate_scope)
            binding = bindings.get((key, name))
            if binding is not None:
                return binding
            if name in declared.get(key, set()):
                return None
        if name in constructors:
            return _Binding("constructor")
        if name in modules:
            return _Binding("module")
        return None

    unresolved = set(declarators)
    changed = True
    while changed:
        changed = False
        for node in tuple(unresolved):
            name_node = node.child_by_field_name("name")
            value = node.child_by_field_name("value")
            if name_node is None or value is None or name_node.type != "identifier":
                unresolved.discard(node)
                continue
            name = _text(source, name_node)
            binding: _Binding | None = None
            if value.type == "new_expression":
                constructor = value.child_by_field_name("constructor")
                chain = _member_chain(source, constructor) if constructor is not None else None
                accepted = chain is not None and (
                    (len(chain) == 1 and lookup(node, chain[0]) == _Binding("constructor"))
                    or (len(chain) == 2 and lookup(node, chain[0]) == _Binding("module") and chain[1] == "OpenAI")
                )
                if accepted:
                    arguments = value.child_by_field_name("arguments")
                    keys = _pair_keys(source, arguments) if arguments is not None else {}
                    features = frozenset({"retries_configured"} if "maxRetries" in keys else set())
                    binding = _Binding("client", features)
            elif value.type == "identifier":
                previous = lookup(node, _text(source, value))
                if previous is not None and previous.kind in {"client", "resource"}:
                    binding = _Binding(previous.kind, previous.features | {"client_alias"})
            elif value.type == "member_expression":
                chain = _member_chain(source, value)
                if chain is not None and len(chain) == 2:
                    previous = lookup(node, chain[0])
                    if previous is not None and previous.kind == "client" and chain[1] == "responses":
                        binding = _Binding("resource", previous.features | {"resource_alias"})
            if binding is not None:
                bindings[(_scope_key(_scope(node)), name)] = binding
                unresolved.discard(node)
                changed = True

    calls: list[DiscoveredCall] = []
    gaps: list[DiscoveryGap] = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        chain = _member_chain(source, function)
        if chain is None:
            raw_function = source[function.start_byte : function.end_byte]
            if (constructors or modules or constructor_declarations) and b"responses" in raw_function:
                gaps.append(
                    DiscoveryGap(
                        "ambiguous_dynamic_callsite",
                        "L0",
                        "Replace computed, optional, or dynamic Responses dispatch with a statically bindable callsite.",
                    )
                )
            continue
        if chain[-3:] == ("chat", "completions", "create"):
            root_binding = lookup(node, chain[0])
            if root_binding is not None and root_binding.kind in {"client", "module"}:
                gaps.append(DiscoveryGap("unsupported_operation", "L0", "Migrate or separately adapt this Chat Completions callsite."))
            continue
        binding: _Binding | None = None
        operation: str | None = None
        if len(chain) == 3 and chain[1] == "responses" and chain[2] in {"create", "parse"}:
            candidate = lookup(node, chain[0])
            if candidate is not None and candidate.kind in {"client", "module"}:
                binding = candidate
                operation = f"responses.{chain[2]}"
            elif constructors or modules:
                gaps.append(DiscoveryGap("ambiguous_dynamic_callsite", "L0", "Bind the OpenAI client or declare a reviewed wrapper before analysis."))
        elif len(chain) == 2 and chain[1] in {"create", "parse"}:
            candidate = lookup(node, chain[0])
            if candidate is not None and candidate.kind == "resource":
                binding = candidate
                operation = f"responses.{chain[1]}"
        if binding is None or operation is None:
            continue
        keys = _pair_keys(source, arguments)
        features = set(binding.features) | {"asynchronous"}
        if "tools" in keys:
            features.add("tools")
        if "stream" in keys and _text(source, keys["stream"]) == "true":
            features.add("streaming")
        if operation == "responses.parse" or keys.keys() & {"text", "response_format"}:
            features.add("structured_output")
        if keys.keys() & {"maxRetries", "max_retries"}:
            features.add("retries_configured")
        if "signal" in keys:
            features.add("cancellation_bounded")
        if _has_catch(source, node):
            features.add("errors_handled")
        symbol, wrapper = _enclosing_symbol(source, node)
        if wrapper:
            features.add("wrapper_body")
        normalized_digest = _normalized_digest(source, node)
        ordinal = sum(
            item.enclosing_symbol == symbol
            and item.operation == operation
            and item.normalized_ast_digest == normalized_digest
            for item in calls
        )
        calls.append(
            DiscoveredCall(
                line=node.start_point.row + 1,
                language=language,
                operation=operation,
                normalized_ast_digest=normalized_digest,
                enclosing_symbol=symbol,
                features=tuple(sorted(features)),
                ast_ordinal=ordinal,
            )
        )

    if anthropic:
        gaps.append(DiscoveryGap("unsupported_provider", "L0", "Use the OpenAI Responses adapter or add a reviewed provider adapter."))
    return DiscoveryResult(tuple(calls), tuple(gaps))
