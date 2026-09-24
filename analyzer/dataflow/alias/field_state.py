"""Flow-sensitive field state map and transfer functions (Phase 17).

Implements field-sensitive object state tracking with strong/weak update
semantics, bounded field overflow handling, and deterministic join operations.
"""

from typing import Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.alias.models import FieldKey, PointsToSet
from analyzer.dataflow.taint.models import TaintState
from analyzer.dataflow.types.models import TypeBinding


class FieldStateEntry(BaseModel):
    """State of a single field on an abstract object at a specific program point."""
    points_to: PointsToSet = Field(default_factory=PointsToSet)
    taint_state: TaintState = TaintState.UNTAINTED
    type_binding: Optional[TypeBinding] = None

    def merge(self, other: "FieldStateEntry", max_candidates: int = 4) -> "FieldStateEntry":
        """Deterministic lattice join of two field state entries."""
        return FieldStateEntry(
            points_to=self.points_to.merge(other.points_to, max_candidates),
            taint_state=TaintState.merge(self.taint_state, other.taint_state),
            type_binding=self.type_binding or other.type_binding,
        )


class FieldStateMap(BaseModel):
    """Flow-sensitive map from (context_id, FieldKey) to field state.

    Implements strong/weak update semantics for field writes and
    deterministic join operations for branch merges.
    """
    entries: dict[str, FieldStateEntry] = Field(default_factory=dict)
    field_counts: dict[str, int] = Field(default_factory=dict)  # object_id -> count of distinct fields
    max_fields_per_object: int = 16
    max_points_to_candidates: int = 4
    overflow_objects: set[str] = Field(default_factory=set)  # object_ids that exceeded field budget

    def _make_key(self, context_id: str, field_key: FieldKey) -> str:
        """Create a deterministic composite key."""
        return f"{context_id}:{field_key.object_id}.{field_key.field_name}"

    def _track_field_count(self, object_id: str, field_name: str) -> bool:
        """Track field count per object. Returns False if overflow."""
        current = self.field_counts.get(object_id, 0)
        # Check if this field already exists for this object
        existing_prefix = f"{object_id}.{field_name}"
        for key in self.entries:
            if existing_prefix in key:
                return True  # Already tracked field
        if current >= self.max_fields_per_object:
            self.overflow_objects.add(object_id)
            return False
        self.field_counts[object_id] = current + 1
        return True

    def strong_update(
        self,
        context_id: str,
        field_key: FieldKey,
        points_to: PointsToSet,
        taint_state: TaintState,
        type_binding: Optional[TypeBinding] = None,
    ) -> None:
        """Strong update: overwrite field state for a singleton receiver."""
        if not self._track_field_count(field_key.object_id, field_key.field_name):
            return  # Field budget exceeded
        composite = self._make_key(context_id, field_key)
        self.entries[composite] = FieldStateEntry(
            points_to=points_to,
            taint_state=taint_state,
            type_binding=type_binding,
        )

    def weak_update(
        self,
        context_id: str,
        field_key: FieldKey,
        points_to: PointsToSet,
        taint_state: TaintState,
        type_binding: Optional[TypeBinding] = None,
    ) -> None:
        """Weak update: merge with existing field state for ambiguous receivers."""
        if not self._track_field_count(field_key.object_id, field_key.field_name):
            return  # Field budget exceeded
        composite = self._make_key(context_id, field_key)
        new_entry = FieldStateEntry(
            points_to=points_to,
            taint_state=taint_state,
            type_binding=type_binding,
        )
        existing = self.entries.get(composite)
        if existing:
            self.entries[composite] = existing.merge(new_entry, self.max_points_to_candidates)
        else:
            self.entries[composite] = new_entry

    def read_field(
        self,
        context_id: str,
        field_key: FieldKey,
    ) -> FieldStateEntry:
        """Read field state. Returns unknown state for overflow or unmodeled fields."""
        if field_key.object_id in self.overflow_objects:
            # Check if this specific field was tracked before overflow
            composite = self._make_key(context_id, field_key)
            entry = self.entries.get(composite)
            if entry:
                return entry
            # Unmodeled field on overflow object
            return FieldStateEntry(
                points_to=PointsToSet(is_unknown=True),
                taint_state=TaintState.UNKNOWN,
            )
        composite = self._make_key(context_id, field_key)
        return self.entries.get(composite, FieldStateEntry())

    def read_field_merged(
        self,
        context_id: str,
        object_ids: list[str],
        field_name: str,
    ) -> FieldStateEntry:
        """Read field across multiple candidate objects and merge results."""
        if not object_ids:
            return FieldStateEntry(
                points_to=PointsToSet(is_unknown=True),
                taint_state=TaintState.UNKNOWN,
            )
        result: Optional[FieldStateEntry] = None
        for oid in sorted(object_ids):
            fk = FieldKey(object_id=oid, field_name=field_name)
            entry = self.read_field(context_id, fk)
            if result is None:
                result = entry
            else:
                result = result.merge(entry, self.max_points_to_candidates)
        return result or FieldStateEntry()

    def write_field_for_receiver(
        self,
        context_id: str,
        receiver_candidate_ids: list[str],
        field_name: str,
        points_to: PointsToSet,
        taint_state: TaintState,
        type_binding: Optional[TypeBinding] = None,
    ) -> None:
        """Write a field value with automatic strong/weak update selection.

        - Singleton receiver: strong update (overwrite).
        - Multi-candidate receiver: weak update (merge) for each candidate.
        """
        if not receiver_candidate_ids:
            return
        for oid in sorted(receiver_candidate_ids):
            fk = FieldKey(object_id=oid, field_name=field_name)
            if len(receiver_candidate_ids) == 1:
                self.strong_update(context_id, fk, points_to, taint_state, type_binding)
            else:
                self.weak_update(context_id, fk, points_to, taint_state, type_binding)

    def merge(self, other: "FieldStateMap") -> "FieldStateMap":
        """Deterministic lattice join of two field state maps for branch merging."""
        merged_entries: dict[str, FieldStateEntry] = {}
        all_keys = sorted(set(list(self.entries.keys()) + list(other.entries.keys())))
        for key in all_keys:
            lhs = self.entries.get(key)
            rhs = other.entries.get(key)
            if lhs and rhs:
                merged_entries[key] = lhs.merge(rhs, self.max_points_to_candidates)
            elif lhs:
                merged_entries[key] = lhs
            else:
                merged_entries[key] = rhs  # type: ignore[assignment]

        merged_counts: dict[str, int] = {}
        all_obj_keys = sorted(set(list(self.field_counts.keys()) + list(other.field_counts.keys())))
        for ok in all_obj_keys:
            merged_counts[ok] = max(self.field_counts.get(ok, 0), other.field_counts.get(ok, 0))

        return FieldStateMap(
            entries=merged_entries,
            field_counts=merged_counts,
            max_fields_per_object=self.max_fields_per_object,
            max_points_to_candidates=self.max_points_to_candidates,
            overflow_objects=self.overflow_objects | other.overflow_objects,
        )

    def copy(self) -> "FieldStateMap":
        """Create an independent copy for branch analysis."""
        return FieldStateMap(
            entries={k: FieldStateEntry(
                points_to=v.points_to.copy(),
                taint_state=v.taint_state,
                type_binding=v.type_binding,
            ) for k, v in self.entries.items()},
            field_counts=dict(self.field_counts),
            max_fields_per_object=self.max_fields_per_object,
            max_points_to_candidates=self.max_points_to_candidates,
            overflow_objects=set(self.overflow_objects),
        )

    def get_field_edges_count(self) -> int:
        """Return total number of tracked field state entries."""
        return len(self.entries)

    def get_truncated_count(self) -> int:
        """Return number of overflow objects."""
        return len(self.overflow_objects)
