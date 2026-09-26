"""Security property lattice and transition semantics for CodeSentinel (Phase 23).

Maintains discrete, context-specific security properties and defines conservative
lattice join/meet operations ensuring UNKNOWN never silently transitions into SAFE.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Optional, Set
from pydantic import BaseModel, ConfigDict, Field
from analyzer.dataflow.taint.models import SinkCategory


class SecurityProperty(str, Enum):
    """Discrete security property held by a value or expression."""
    UNTRUSTED = "UNTRUSTED"
    VALIDATED_TYPE = "VALIDATED_TYPE"      # Scalar numeric/boolean cast
    TYPE_COERCED = "TYPE_COERCED"          # Explicit type coercion applied
    VALIDATED_FORMAT = "VALIDATED_FORMAT"  # Constrained by regex or whitelist
    VALIDATED_RANGE = "VALIDATED_RANGE"    # Bounds checked
    VALIDATED_ENUM = "VALIDATED_ENUM"      # Membership in literal set
    SQL_SAFE = "SQL_SAFE"                  # Parameterized or safely escaped for SQL
    COMMAND_SAFE = "COMMAND_SAFE"          # Shell-quoted or argument vector
    SHELL_QUOTED = "SHELL_QUOTED"          # Quoted with shlex
    HTML_SAFE = "HTML_SAFE"                # Escaped or stripped of executable HTML/DOM
    HTML_ESCAPED = "HTML_ESCAPED"          # HTML escaped
    URL_SAFE = "URL_SAFE"                  # URL-encoded or scheme-whitelisted
    PATH_SAFE = "PATH_SAFE"                # Normalized or whitelisted path
    PATH_NORMALIZED = "PATH_NORMALIZED"    # Path normalized
    AUTHENTICATED = "AUTHENTICATED"        # Session identity established
    AUTHORIZED = "AUTHORIZED"              # Permission verified for operation
    UNKNOWN = "UNKNOWN"                    # Unresolved / indeterminate property


class SecurityPropertyState(BaseModel):
    """Collection of security properties held along an execution path."""
    model_config = ConfigDict(frozen=False)

    properties: Set[SecurityProperty] = Field(default_factory=lambda: {SecurityProperty.UNTRUSTED})

    def has_property(self, prop: SecurityProperty) -> bool:
        if prop in self.properties:
            return True
        # Aliases
        if prop == SecurityProperty.TYPE_COERCED and SecurityProperty.VALIDATED_TYPE in self.properties:
            return True
        if prop == SecurityProperty.VALIDATED_TYPE and SecurityProperty.TYPE_COERCED in self.properties:
            return True
        if prop == SecurityProperty.HTML_SAFE and SecurityProperty.HTML_ESCAPED in self.properties:
            return True
        if prop == SecurityProperty.HTML_ESCAPED and SecurityProperty.HTML_SAFE in self.properties:
            return True
        if prop == SecurityProperty.COMMAND_SAFE and SecurityProperty.SHELL_QUOTED in self.properties:
            return True
        if prop == SecurityProperty.SHELL_QUOTED and SecurityProperty.COMMAND_SAFE in self.properties:
            return True
        if prop == SecurityProperty.PATH_SAFE and SecurityProperty.PATH_NORMALIZED in self.properties:
            return True
        if prop == SecurityProperty.PATH_NORMALIZED and SecurityProperty.PATH_SAFE in self.properties:
            return True
        return False

    def add_property(self, prop: SecurityProperty) -> SecurityPropertyState:
        """Add property to state."""
        self.properties.add(prop)
        if prop == SecurityProperty.TYPE_COERCED:
            self.properties.add(SecurityProperty.VALIDATED_TYPE)
            self.properties.add(SecurityProperty.SQL_SAFE)
        elif prop == SecurityProperty.VALIDATED_TYPE:
            self.properties.add(SecurityProperty.TYPE_COERCED)
            self.properties.add(SecurityProperty.SQL_SAFE)
        elif prop == SecurityProperty.PATH_NORMALIZED:
            self.properties.add(SecurityProperty.PATH_SAFE)
        elif prop == SecurityProperty.HTML_ESCAPED:
            self.properties.add(SecurityProperty.HTML_SAFE)
        elif prop == SecurityProperty.SHELL_QUOTED:
            self.properties.add(SecurityProperty.COMMAND_SAFE)
        return self

    def is_safe_for_sink(self, sink_category: SinkCategory) -> bool:
        """Evaluate if the current state satisfies requirements for a target sink."""
        if self.has_property(SecurityProperty.VALIDATED_TYPE) or self.has_property(SecurityProperty.TYPE_COERCED):
            return True

        if sink_category == SinkCategory.SQL_EXECUTE:
            return self.has_property(SecurityProperty.SQL_SAFE)
        elif sink_category == SinkCategory.COMMAND_EXECUTE:
            return self.has_property(SecurityProperty.COMMAND_SAFE) or self.has_property(SecurityProperty.SHELL_QUOTED)
        elif sink_category == SinkCategory.DOM_INJECTION:
            return self.has_property(SecurityProperty.HTML_SAFE) or self.has_property(SecurityProperty.HTML_ESCAPED)
        elif sink_category == SinkCategory.CODE_EVAL:
            return (
                self.has_property(SecurityProperty.VALIDATED_TYPE)
                or self.has_property(SecurityProperty.VALIDATED_FORMAT)
                or self.has_property(SecurityProperty.VALIDATED_ENUM)
            )
        elif sink_category == SinkCategory.FILE_PATH:
            return (
                self.has_property(SecurityProperty.PATH_SAFE)
                or self.has_property(SecurityProperty.PATH_NORMALIZED)
                or self.has_property(SecurityProperty.VALIDATED_TYPE)
                or self.has_property(SecurityProperty.VALIDATED_ENUM)
            )
        return False

    def with_property(self, prop: SecurityProperty) -> SecurityPropertyState:
        """Return a new state with the added property."""
        new_props = set(self.properties)
        new_props.add(prop)
        return SecurityPropertyState(properties=new_props)

    def without_property(self, prop: SecurityProperty) -> SecurityPropertyState:
        """Return a new state with the specified property removed."""
        new_props = set(self.properties)
        new_props.discard(prop)
        return SecurityPropertyState(properties=new_props)

    def derive_from_expression(self, expr: str) -> SecurityPropertyState:
        """Statically inspect an expression string and enrich state with properties."""
        e = expr.strip()
        new_props = set(self.properties)
        # Type casts
        if e.startswith(("int(", "float(", "bool(", "Number(", "parseInt(", "parseFloat(")):
            new_props.add(SecurityProperty.VALIDATED_TYPE)
            new_props.add(SecurityProperty.TYPE_COERCED)
            new_props.add(SecurityProperty.SQL_SAFE)
        # Range checks
        if any(op in e for op in [">=", "<=", ">", "<"]) and any(w in e for w in ["and", "&&"]):
            new_props.add(SecurityProperty.VALIDATED_RANGE)
        # Enum / containment checks
        if " in " in e or ".includes(" in e or ".has(" in e:
            new_props.add(SecurityProperty.VALIDATED_ENUM)
        # Shell escapes
        if "shlex.quote(" in e or "quote(" in e:
            new_props.add(SecurityProperty.COMMAND_SAFE)
            new_props.add(SecurityProperty.SHELL_QUOTED)
        # HTML escapes
        if "html.escape(" in e or "escape(" in e or "DOMPurify.sanitize(" in e:
            new_props.add(SecurityProperty.HTML_SAFE)
            new_props.add(SecurityProperty.HTML_ESCAPED)
        # URL escapes
        if "urllib.parse.quote(" in e or "encodeURIComponent(" in e:
            new_props.add(SecurityProperty.URL_SAFE)
        # SQL literal wrappers
        if "psycopg2.sql.Literal(" in e or "sql.Literal(" in e:
            new_props.add(SecurityProperty.SQL_SAFE)
        # Path validation
        if "os.path.basename(" in e or "path.basename(" in e or "os.path.abspath(" in e:
            new_props.add(SecurityProperty.PATH_SAFE)
            new_props.add(SecurityProperty.PATH_NORMALIZED)
        return SecurityPropertyState(properties=new_props)

    def join(self, other: SecurityPropertyState) -> SecurityPropertyState:
        """Conservative lattice join across branches."""
        return self.__class__.join_states(self, other)

    @classmethod
    def join_states(cls, state1: SecurityPropertyState, state2: SecurityPropertyState) -> SecurityPropertyState:
        """Conservative lattice join across branches."""
        props1 = state1.properties
        props2 = state2.properties

        result_props: Set[SecurityProperty] = set()

        if SecurityProperty.UNTRUSTED in props1 or SecurityProperty.UNTRUSTED in props2:
            result_props.add(SecurityProperty.UNTRUSTED)

        if SecurityProperty.UNKNOWN in props1 or SecurityProperty.UNKNOWN in props2:
            result_props.add(SecurityProperty.UNKNOWN)

        for prop in SecurityProperty:
            if prop in (SecurityProperty.UNTRUSTED, SecurityProperty.UNKNOWN):
                continue
            if state1.has_property(prop) and state2.has_property(prop):
                result_props.add(prop)

        # If neither branch is untrusted and safety properties hold, untrusted is removed
        if SecurityProperty.UNTRUSTED not in props1 and SecurityProperty.UNTRUSTED not in props2:
            result_props.discard(SecurityProperty.UNTRUSTED)

        return cls(properties=result_props)
