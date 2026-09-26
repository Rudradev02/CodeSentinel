"""Unit tests for Phase 24 Validation Provenance, Safe Properties, and Lattice Joins."""

import pytest
from analyzer.dataflow.properties import SecurityProperty, SecurityPropertyState
from analyzer.dataflow.taint.models import SinkCategory


def test_derive_from_type_coercion_expressions():
    """Verify derive_from_expression captures integer, float, and numeric casts."""
    st = SecurityPropertyState()
    st1 = st.derive_from_expression("int(request.args.get('id'))")
    assert st1.has_property(SecurityProperty.TYPE_COERCED)
    assert st1.has_property(SecurityProperty.SQL_SAFE)
    assert st1.has_property(SecurityProperty.VALIDATED_TYPE)

    st2 = st.derive_from_expression("parseInt(req.query.limit, 10)")
    assert st2.has_property(SecurityProperty.TYPE_COERCED)
    assert st2.has_property(SecurityProperty.SQL_SAFE)
    assert st2.has_property(SecurityProperty.VALIDATED_TYPE)


def test_derive_from_range_and_enum_expressions():
    """Verify derive_from_expression identifies range guards and enum containment."""
    st = SecurityPropertyState()
    st_range = st.derive_from_expression("offset >= 0 and offset <= 1000")
    assert st_range.has_property(SecurityProperty.VALIDATED_RANGE)

    st_enum = st.derive_from_expression("status in ['PENDING', 'APPROVED', 'REJECTED']")
    assert st_enum.has_property(SecurityProperty.VALIDATED_ENUM)


def test_derive_from_path_sanitization_expressions():
    """Verify derive_from_expression extracts PATH_NORMALIZED and PATH_SAFE."""
    st = SecurityPropertyState()
    st_path = st.derive_from_expression("os.path.basename(user_path)")
    assert st_path.has_property(SecurityProperty.PATH_NORMALIZED)
    assert st_path.has_property(SecurityProperty.PATH_SAFE)

    assert st_path.is_safe_for_sink(SinkCategory.FILE_PATH)


def test_lattice_join_preservation_and_unknown_widening():
    """Verify conservative lattice join of security properties across branches."""
    # Branch A: int cast (safe for SQL)
    st_a = SecurityPropertyState()
    st_a.add_property(SecurityProperty.TYPE_COERCED)
    st_a.add_property(SecurityProperty.SQL_SAFE)

    # Branch B: also int cast
    st_b = SecurityPropertyState()
    st_b.add_property(SecurityProperty.TYPE_COERCED)
    st_b.add_property(SecurityProperty.SQL_SAFE)

    joined_safe = st_a.join(st_b)
    assert joined_safe.has_property(SecurityProperty.SQL_SAFE)
    assert SecurityProperty.UNKNOWN not in joined_safe.properties

    # Branch C: raw untrusted string
    st_c = SecurityPropertyState()
    st_c.add_property(SecurityProperty.UNKNOWN)

    joined_unsafe = st_a.join(st_c)
    assert not joined_unsafe.has_property(SecurityProperty.SQL_SAFE)
    assert SecurityProperty.UNKNOWN in joined_unsafe.properties
