"""Declarative catalog and registry of taint sources, sinks, and sanitizers."""

from typing import Optional
from analyzer.dataflow.taint.models import (
    SinkCategory,
    SourceCategory,
    TaintSanitizer,
    TaintSink,
    TaintSource,
)
from analyzer.models.findings import FindingConfidence, FindingSeverity


class TaintRegistry:
    """Registry maintaining declarative sources, sinks, and context-specific sanitizers."""

    def __init__(self, load_defaults: bool = True):
        self._sources: list[TaintSource] = []
        self._sinks: list[TaintSink] = []
        self._sanitizers: list[TaintSanitizer] = []

        if load_defaults:
            self._load_python_defaults()
            self._load_javascript_defaults()

    def register_source(self, source: TaintSource) -> None:
        self._sources.append(source)

    def register_sink(self, sink: TaintSink) -> None:
        self._sinks.append(sink)

    def register_sanitizer(self, sanitizer: TaintSanitizer) -> None:
        self._sanitizers.append(sanitizer)

    def get_sources(self, language: Optional[str] = None) -> list[TaintSource]:
        if not language:
            return list(self._sources)
        lang_upper = language.upper()
        return [s for s in self._sources if s.language.upper() == lang_upper]

    def get_sinks(self, language: Optional[str] = None, rule_id: Optional[str] = None) -> list[TaintSink]:
        res = self._sinks
        if language:
            lang_upper = language.upper()
            res = [s for s in res if s.language.upper() == lang_upper]
        if rule_id:
            res = [s for s in res if s.rule_id == rule_id]
        return res

    def get_sanitizers(self, language: Optional[str] = None, target_category: Optional[SinkCategory] = None) -> list[TaintSanitizer]:
        res = self._sanitizers
        if language:
            lang_upper = language.upper()
            res = [s for s in res if s.language.upper() == lang_upper]
        if target_category:
            res = [s for s in res if target_category in s.effective_categories]
        return res

    def find_matching_source(
        self,
        language: str,
        base_object: Optional[str],
        member: Optional[str],
        pattern_type: str,
    ) -> Optional[TaintSource]:
        """Match an AST access against registered sources."""
        lang_upper = language.upper()
        for src in self._sources:
            if src.language.upper() != lang_upper:
                continue
            if src.pattern_type != pattern_type:
                continue
            if base_object and src.base_object.lower() == base_object.lower():
                if member and src.member.lower() == member.lower():
                    return src
        return None

    def find_matching_sink(
        self,
        language: str,
        callee_name: str,
        receiver_name: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> Optional[TaintSink]:
        """Match a call expression against registered sinks."""
        lang_upper = language.upper()
        for sink in self._sinks:
            if sink.language.upper() != lang_upper:
                continue
            if rule_id and sink.rule_id != rule_id:
                continue
            if sink.callee_name.lower() == callee_name.lower():
                if sink.module_or_object is None:
                    return sink
                if receiver_name and sink.module_or_object.lower() in receiver_name.lower():
                    return sink
        return None

    def find_matching_sanitizer(
        self,
        language: str,
        callee_name: str,
        target_category: SinkCategory,
    ) -> Optional[TaintSanitizer]:
        """Match a sanitizer call against registered sanitizers for a specific sink category."""
        lang_upper = language.upper()
        for san in self._sanitizers:
            if san.language.upper() != lang_upper:
                continue
            if target_category in san.effective_categories:
                # Support pattern match (e.g. "int", "shlex.quote", "DOMPurify.sanitize")
                pat = san.callee_pattern.lower()
                c_name = callee_name.lower()
                if pat == c_name or c_name.endswith(f".{pat}") or pat.endswith(f".{c_name}"):
                    return san
        return None

    def _load_python_defaults(self) -> None:
        # Flask / Django Sources
        for member in ["args", "values", "form", "GET", "POST", "COOKIES"]:
            self.register_source(
                TaintSource(
                    source_id=f"HTTP_PARAM_{member.upper()}",
                    language="PYTHON",
                    category=SourceCategory.HTTP_PARAM,
                    framework="FLASK_DJANGO",
                    pattern_type="SUBSCRIPT",
                    base_object="request",
                    member=member,
                    description=f"Untrusted HTTP parameter via request.{member}",
                )
            )
            self.register_source(
                TaintSource(
                    source_id=f"HTTP_ATTR_{member.upper()}",
                    language="PYTHON",
                    category=SourceCategory.HTTP_PARAM,
                    framework="FLASK_DJANGO",
                    pattern_type="ATTRIBUTE",
                    base_object="request",
                    member=member,
                    description=f"Untrusted HTTP dictionary via request.{member}",
                )
            )

        for member in ["get_json", "json", "data"]:
            self.register_source(
                TaintSource(
                    source_id=f"HTTP_BODY_{member.upper()}",
                    language="PYTHON",
                    category=SourceCategory.HTTP_BODY,
                    framework="FLASK",
                    pattern_type="CALL" if member == "get_json" else "ATTRIBUTE",
                    base_object="request",
                    member=member,
                    description=f"Untrusted HTTP body payload via request.{member}",
                )
            )

        # Environment & CLI inputs
        self.register_source(
            TaintSource(
                source_id="ENV_VAR_SUBSCRIPT",
                language="PYTHON",
                category=SourceCategory.ENV_VAR,
                pattern_type="SUBSCRIPT",
                base_object="os.environ",
                member="environ",
                description="Environment variable read via os.environ[...]",
            )
        )
        self.register_source(
            TaintSource(
                source_id="ENV_VAR_GET",
                language="PYTHON",
                category=SourceCategory.ENV_VAR,
                pattern_type="CALL",
                base_object="os",
                member="getenv",
                description="Environment variable read via os.getenv(...)",
            )
        )

        # Python Sinks: SEC-PY-009 (SQL Injection)
        for obj in ["cursor", "connection", "engine", "session", "db", "conn"]:
            self.register_sink(
                TaintSink(
                    sink_id=f"SQL_EXECUTE_{obj.upper()}",
                    language="PYTHON",
                    category=SinkCategory.SQL_EXECUTE,
                    rule_id="SEC-PY-009",
                    callee_name="execute",
                    module_or_object=obj,
                    vulnerable_arg_indices=[0],
                    supports_parameter_binding=True,
                    parameter_binding_arg_index=1,
                    description=f"Database query execution via {obj}.execute()",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )
            self.register_sink(
                TaintSink(
                    sink_id=f"SQL_EXECUTEMANY_{obj.upper()}",
                    language="PYTHON",
                    category=SinkCategory.SQL_EXECUTE,
                    rule_id="SEC-PY-009",
                    callee_name="executemany",
                    module_or_object=obj,
                    vulnerable_arg_indices=[0],
                    supports_parameter_binding=True,
                    parameter_binding_arg_index=1,
                    description=f"Batch database query execution via {obj}.executemany()",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )

        # Python Sinks: SEC-PY-010 (Command Injection)
        for fn in ["run", "Popen", "call", "check_output", "check_call"]:
            self.register_sink(
                TaintSink(
                    sink_id=f"SUBPROCESS_{fn.upper()}",
                    language="PYTHON",
                    category=SinkCategory.COMMAND_EXECUTE,
                    rule_id="SEC-PY-010",
                    callee_name=fn,
                    module_or_object="subprocess",
                    vulnerable_arg_indices=[0],
                    supports_parameter_binding=False,
                    description=f"Subprocess command execution via subprocess.{fn}()",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )
        for fn in ["system", "popen"]:
            self.register_sink(
                TaintSink(
                    sink_id=f"OS_{fn.upper()}",
                    language="PYTHON",
                    category=SinkCategory.COMMAND_EXECUTE,
                    rule_id="SEC-PY-010",
                    callee_name=fn,
                    module_or_object="os",
                    vulnerable_arg_indices=[0],
                    supports_parameter_binding=False,
                    description=f"Shell command execution via os.{fn}()",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )

        # Python Sanitizers
        self.register_sanitizer(
            TaintSanitizer(
                sanitizer_id="PY_INT_CONSTRAINT",
                language="PYTHON",
                effective_categories=[SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE],
                callee_pattern="int",
                description="Integer cast constraining value to numeric representation",
                strength="NUMERIC_CONSTRAINT",
            )
        )
        self.register_sanitizer(
            TaintSanitizer(
                sanitizer_id="PY_FLOAT_CONSTRAINT",
                language="PYTHON",
                effective_categories=[SinkCategory.SQL_EXECUTE, SinkCategory.COMMAND_EXECUTE],
                callee_pattern="float",
                description="Float cast constraining value to numeric representation",
                strength="NUMERIC_CONSTRAINT",
            )
        )
        self.register_sanitizer(
            TaintSanitizer(
                sanitizer_id="PY_SHLEX_QUOTE",
                language="PYTHON",
                effective_categories=[SinkCategory.COMMAND_EXECUTE],
                callee_pattern="shlex.quote",
                description="POSIX shell quoting escaping shell metacharacters",
                strength="SHELL_ESCAPE",
            )
        )

    def _load_javascript_defaults(self) -> None:
        # Browser & Express Sources
        for mem in ["search", "hash", "href", "pathname"]:
            self.register_source(
                TaintSource(
                    source_id=f"JS_LOCATION_{mem.upper()}",
                    language="JAVASCRIPT",
                    category=SourceCategory.DOM_INPUT,
                    pattern_type="ATTRIBUTE",
                    base_object="location",
                    member=mem,
                    description=f"Untrusted DOM input via location.{mem}",
                )
            )
        self.register_source(
            TaintSource(
                source_id="JS_COOKIE",
                language="JAVASCRIPT",
                category=SourceCategory.COOKIE,
                pattern_type="ATTRIBUTE",
                base_object="document",
                member="cookie",
                description="Document cookie string",
            )
        )
        for p in ["query", "params", "body", "headers"]:
            self.register_source(
                TaintSource(
                    source_id=f"EXPRESS_{p.upper()}",
                    language="JAVASCRIPT",
                    category=SourceCategory.HTTP_PARAM,
                    framework="EXPRESS",
                    pattern_type="ATTRIBUTE",
                    base_object="req",
                    member=p,
                    description=f"Express request object property req.{p}",
                )
            )

        # JS Sinks: SEC-JS-007 (DOM XSS)
        for sink_attr in ["innerHTML", "outerHTML"]:
            self.register_sink(
                TaintSink(
                    sink_id=f"DOM_{sink_attr.upper()}",
                    language="JAVASCRIPT",
                    category=SinkCategory.DOM_INJECTION,
                    rule_id="SEC-JS-007",
                    callee_name=sink_attr,
                    module_or_object="element",
                    vulnerable_arg_indices=[0],
                    description=f"Dangerous DOM HTML assignment to {sink_attr}",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )
        for doc_fn in ["write", "writeln"]:
            self.register_sink(
                TaintSink(
                    sink_id=f"DOC_{doc_fn.upper()}",
                    language="JAVASCRIPT",
                    category=SinkCategory.DOM_INJECTION,
                    rule_id="SEC-JS-007",
                    callee_name=doc_fn,
                    module_or_object="document",
                    vulnerable_arg_indices=[0],
                    description=f"Dangerous DOM write via document.{doc_fn}()",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.HIGH,
                )
            )

        # JS Sinks: SEC-JS-008 (Dynamic Eval)
        self.register_sink(
            TaintSink(
                sink_id="EVAL_GLOBAL",
                language="JAVASCRIPT",
                category=SinkCategory.CODE_EVAL,
                rule_id="SEC-JS-008",
                callee_name="eval",
                module_or_object=None,
                vulnerable_arg_indices=[0],
                description="Dynamic script execution via eval()",
                severity=FindingSeverity.CRITICAL,
                confidence=FindingConfidence.HIGH,
            )
        )
        self.register_sink(
            TaintSink(
                sink_id="FUNCTION_CONSTRUCTOR",
                language="JAVASCRIPT",
                category=SinkCategory.CODE_EVAL,
                rule_id="SEC-JS-008",
                callee_name="Function",
                module_or_object=None,
                vulnerable_arg_indices=[-1],  # Any argument to Function constructor
                description="Dynamic function compilation via Function constructor",
                severity=FindingSeverity.CRITICAL,
                confidence=FindingConfidence.HIGH,
            )
        )

        # JS Sanitizers
        self.register_sanitizer(
            TaintSanitizer(
                sanitizer_id="DOMPURIFY_SANITIZE",
                language="JAVASCRIPT",
                effective_categories=[SinkCategory.DOM_INJECTION],
                callee_pattern="DOMPurify.sanitize",
                description="HTML sanitizer stripping executable script elements",
                strength="HTML_STRIP",
            )
        )
        self.register_sanitizer(
            TaintSanitizer(
                sanitizer_id="ENCODE_URI_COMPONENT",
                language="JAVASCRIPT",
                effective_categories=[SinkCategory.DOM_INJECTION],
                callee_pattern="encodeURIComponent",
                description="URI parameter percent-encoding",
                strength="URI_ENCODE",
            )
        )
        for num_cast in ["parseInt", "parseFloat", "Number"]:
            self.register_sanitizer(
                TaintSanitizer(
                    sanitizer_id=f"JS_{num_cast.upper()}",
                    language="JAVASCRIPT",
                    effective_categories=[SinkCategory.DOM_INJECTION, SinkCategory.CODE_EVAL],
                    callee_pattern=num_cast,
                    description=f"Numeric constraint cast via {num_cast}()",
                    strength="NUMERIC_CONSTRAINT",
                )
            )
