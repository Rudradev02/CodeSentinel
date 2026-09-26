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
    VALIDATED_FORMAT = "VALIDATED_FORMAT"  # Constrained by regex or whitelist
    SQL_SAFE = "SQL_SAFE"                  # Parameterized or safely escaped for SQL
    COMMAND_SAFE = "COMMAND_SAFE"          # Shell-quoted or argument vector
    HTML_SAFE = "HTML_SAFE"                # Escaped or stripped of executable HTML/DOM
    URL_SAFE = "URL_SAFE"                  # URL-encoded or scheme-whitelisted
    AUTHENTICATED = "AUTHENTICATED"        # Session identity established
    AUTHORIZED = "AUTHORIZED"              # Permission verified for operation
    UNKNOWN = "UNKNOWN"                    # Unresolved / indeterminate property


class SecurityPropertyState(BaseModel):
    """Immutable collection of security properties held along an execution path."""
    model_config = ConfigDict(frozen=True)

    properties: Set[SecurityProperty] = Field(default_factory=lambda: {SecurityProperty.UNTRUSTED})

    def has_property(self, prop: SecurityProperty) -> bool:
        return prop in self.properties

    def is_safe_for_sink(self, sink_category: SinkCategory) -> bool:
        """Evaluate if the current state satisfies requirements for a target sink."""
        if SecurityProperty.VALIDATED_TYPE in self.properties:
            # Numeric scalar constraints are safe for SQL, command, eval, DOM
            return True

        if sink_category == SinkCategory.SQL_EXECUTE:
            return SecurityProperty.SQL_SAFE in self.properties
        elif sink_category == SinkCategory.COMMAND_EXECUTE:
            return SecurityProperty.COMMAND_SAFE in self.properties
        elif sink_category == SinkCategory.DOM_INJECTION:
            return SecurityProperty.HTML_SAFE in self.properties
        elif sink_category == SinkCategory.CODE_EVAL:
            return (
                SecurityProperty.VALIDATED_TYPE in self.properties
                or SecurityProperty.VALIDATED_FORMAT in self.properties
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

    @classmethod
    def join(cls, state1: SecurityPropertyState, state2: SecurityPropertyState) -> SecurityPropertyState:
        """Conservative lattice join across branches.

        Rules:
        - UNTRUSTED persists if either branch is untrusted.
        - UNKNOWN persists if either branch is unknown.
        - Specific safety properties (e.g. SQL_SAFE) hold only if BOTH branches hold it.
        """
        props1 = state1.properties
        props2 = state2.properties

        result_props: Set[SecurityProperty] = set()

        # If either branch has UNTRUSTED, the joined state remains UNTRUSTED
        if SecurityProperty.UNTRUSTED in props1 or SecurityProperty.UNTRUSTED in props2:
            result_props.add(SecurityProperty.UNTRUSTED)

        # If either branch is UNKNOWN, the uncertainty persists
        if SecurityProperty.UNKNOWN in props1 or SecurityProperty.UNKNOWN in props2:
            result_props.add(SecurityProperty.UNKNOWN)

        # Safety properties must be satisfied on BOTH branches
        for prop in [
            SecurityProperty.VALIDATED_TYPE,
            SecurityProperty.VALIDATED_FORMAT,
            SecurityProperty.SQL_SAFE,
            SecurityProperty.COMMAND_SAFE,
            SecurityProperty.HTML_SAFE,
            SecurityProperty.URL_SAFE,
            SecurityProperty.AUTHENTICATED,
            SecurityProperty.AUTHORIZED,
        ]:
            if prop in props1 and prop in props2:
                result_props.add(prop)

        # If neither branch is untrusted and safety properties hold, untrusted is removed
        if SecurityProperty.UNTRUSTED not in props1 and SecurityProperty.UNTRUSTED not in props2:
            result_props.discard(SecurityProperty.UNTRUSTED)

        return cls(properties=result_props)
