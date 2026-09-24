"""Bounded alias, points-to, and field-sensitive data-flow models (Phase 17).

Implements abstract object identity via allocation-site keying, bounded
PointsToSet lattice with deterministic joins, field-key addressing,
and alias binding evidence for interprocedural propagation.
"""

from enum import Enum
import hashlib
from typing import Optional
from pydantic import BaseModel, Field

from analyzer.dataflow.types.models import TypeBinding, TypeConfidence, TypeOrigin


class ObjectKind(str, Enum):
    """Classification of abstract heap object."""
    ALLOCATION_SITE = "ALLOCATION_SITE"    # Concrete constructor call (x = ClassName() / new ClassName())
    PARAMETER_OBJECT = "PARAMETER_OBJECT"  # Formal parameter reference in function signature
    RETURN_OBJECT = "RETURN_OBJECT"        # Return value placeholder from a callee invocation
    RECEIVER_SELF = "RECEIVER_SELF"        # Implicit instance receiver 'self' or 'this'
    UNKNOWN_OBJECT = "UNKNOWN_OBJECT"      # Dynamic reflection, unannotated external, or unresolvable reference


class AllocationSite(BaseModel):
    """Syntactic allocation site identity for an abstract object."""
    file_path: str                         # Normalized POSIX relative path
    line: int
    col: int = 0
    qualified_class_name: str
    enclosing_function: Optional[str] = None

    def compute_id(self) -> str:
        """Deterministic 16-character SHA-256 allocation site identifier."""
        norm_file = self.file_path.replace("\\", "/")
        seed = f"ALLOC:{norm_file}:{self.line}:{self.col}:{self.qualified_class_name}:{self.enclosing_function or ''}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


class AbstractObject(BaseModel):
    """Represents a bounded abstract heap location."""
    object_id: str                         # Deterministic 16-char SHA-256 hash
    kind: ObjectKind
    type_binding: TypeBinding
    allocation_site: Optional[AllocationSite] = None
    enclosing_function: Optional[str] = None
    parameter_index: Optional[int] = None
    call_site_id: Optional[str] = None
    context_id: Optional[str] = None       # Populated when contextually specialized

    @classmethod
    def create_allocation_site_object(
        cls,
        type_binding: TypeBinding,
        file_path: str,
        line: int,
        col: int,
        enclosing_function: Optional[str] = None,
    ) -> "AbstractObject":
        alloc = AllocationSite(
            file_path=file_path.replace("\\", "/"),
            line=line,
            col=col,
            qualified_class_name=type_binding.qualified_type_name,
            enclosing_function=enclosing_function,
        )
        return cls(
            object_id=alloc.compute_id(),
            kind=ObjectKind.ALLOCATION_SITE,
            type_binding=type_binding,
            allocation_site=alloc,
            enclosing_function=enclosing_function,
        )

    @classmethod
    def create_synthetic_parameter_object(
        cls,
        fn_qualified_name: str,
        param_index: int,
        param_name: str,
        type_binding: TypeBinding,
    ) -> "AbstractObject":
        seed = f"PARAM:{fn_qualified_name}:{param_index}:{param_name}"
        obj_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return cls(
            object_id=obj_id,
            kind=ObjectKind.PARAMETER_OBJECT,
            type_binding=type_binding,
            enclosing_function=fn_qualified_name,
            parameter_index=param_index,
        )

    @classmethod
    def create_synthetic_return_object(
        cls,
        callee_qualified_name: str,
        call_site_file: str,
        call_site_line: int,
        call_site_col: int,
        type_binding: TypeBinding,
        context_id: Optional[str] = None,
    ) -> "AbstractObject":
        norm_file = call_site_file.replace("\\", "/")
        seed = f"RET:{callee_qualified_name}:{norm_file}:{call_site_line}:{call_site_col}:{context_id or 'ROOT'}"
        obj_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return cls(
            object_id=obj_id,
            kind=ObjectKind.RETURN_OBJECT,
            type_binding=type_binding,
            call_site_id=f"{norm_file}:{call_site_line}:{call_site_col}",
            context_id=context_id,
        )

    @classmethod
    def create_receiver_self_object(
        cls,
        enclosing_class: str,
        fn_qualified_name: str,
        type_binding: TypeBinding,
        context_id: Optional[str] = None,
    ) -> "AbstractObject":
        seed = f"SELF:{enclosing_class}:{fn_qualified_name}:{context_id or 'ROOT'}"
        obj_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return cls(
            object_id=obj_id,
            kind=ObjectKind.RECEIVER_SELF,
            type_binding=type_binding,
            enclosing_function=fn_qualified_name,
            context_id=context_id,
        )

    @classmethod
    def create_unknown_object(
        cls,
        file_path: str,
        line: int,
        col: int = 0,
        reason: str = "DYNAMIC",
    ) -> "AbstractObject":
        norm_file = file_path.replace("\\", "/")
        seed = f"UNKNOWN:{norm_file}:{line}:{col}:{reason}"
        obj_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        unknown_type = TypeBinding(
            type_name="Unknown",
            qualified_type_name="Unknown",
            confidence=TypeConfidence.UNKNOWN,
            origin=TypeOrigin.UNRESOLVED,
            source_file=norm_file,
            line=line,
            col=col,
        )
        return cls(
            object_id=obj_id,
            kind=ObjectKind.UNKNOWN_OBJECT,
            type_binding=unknown_type,
            allocation_site=None,
        )


class PointsToSet(BaseModel):
    """Bounded, deterministically ordered set of abstract object references."""
    candidate_ids: list[str] = Field(default_factory=list)  # Sorted deterministically
    is_unknown: bool = False                                # True if set may contain untracked/external objects
    is_ambiguous: bool = False                              # True if multiple statically possible objects exist
    is_truncated: bool = False                              # True if candidate budget limit was exceeded

    def add_object(self, object_id: str, max_candidates: int = 4) -> None:
        if object_id not in self.candidate_ids:
            if len(self.candidate_ids) >= max_candidates:
                self.is_ambiguous = True
                self.is_truncated = True
                return
            self.candidate_ids.append(object_id)
            self.candidate_ids.sort()
            if len(self.candidate_ids) > 1:
                self.is_ambiguous = True

    def merge(self, other: "PointsToSet", max_candidates: int = 4) -> "PointsToSet":
        """Deterministic lattice join of two PointsToSet domains."""
        combined = sorted(list(set(self.candidate_ids + other.candidate_ids)))
        is_trunc = self.is_truncated or other.is_truncated or len(combined) > max_candidates
        final_ids = combined[:max_candidates]
        is_ambig = self.is_ambiguous or other.is_ambiguous or len(final_ids) > 1
        return PointsToSet(
            candidate_ids=final_ids,
            is_unknown=self.is_unknown or other.is_unknown,
            is_ambiguous=is_ambig,
            is_truncated=is_trunc,
        )

    def is_singleton(self) -> bool:
        """True if this points-to set unambiguously refers to exactly one object."""
        return len(self.candidate_ids) == 1 and not self.is_unknown and not self.is_ambiguous

    def is_empty(self) -> bool:
        """True if no candidate targets are known."""
        return len(self.candidate_ids) == 0 and not self.is_unknown

    def copy(self) -> "PointsToSet":
        """Create an independent deep copy of this PointsToSet."""
        return PointsToSet(
            candidate_ids=list(self.candidate_ids),
            is_unknown=self.is_unknown,
            is_ambiguous=self.is_ambiguous,
            is_truncated=self.is_truncated,
        )


class FieldKey(BaseModel):
    """Deterministic key addressing a field on an abstract object."""
    object_id: str
    field_name: str

    def to_string_key(self) -> str:
        return f"{self.object_id}.{self.field_name}"


class AliasBinding(BaseModel):
    """Metadata describing a resolved alias relationship between symbols or fields."""
    source_symbol: str
    target_symbol: str
    source_field: Optional[str] = None
    target_field: Optional[str] = None
    confidence: TypeConfidence
    line: int
    col: int = 0


class AliasEnvironment(BaseModel):
    """Scoped alias environment mapping variables to bounded PointsToSets.

    Maintains flow-sensitive variable-to-object mappings within a function scope.
    Each variable maps to a PointsToSet indicating which abstract objects it may reference.
    """
    bindings: dict[str, PointsToSet] = Field(default_factory=dict)
    alias_evidence: list[AliasBinding] = Field(default_factory=list)
    object_store: dict[str, AbstractObject] = Field(default_factory=dict)
    objects_allocated: int = 0
    max_objects_per_function: int = 32
    max_points_to_candidates: int = 4
    is_truncated: bool = False

    def set_points_to(self, symbol: str, pts: PointsToSet) -> None:
        """Strong update: replace the points-to set for a symbol."""
        self.bindings[symbol] = pts

    def get_points_to(self, symbol: str) -> PointsToSet:
        """Return the points-to set for a symbol, or empty if unknown."""
        return self.bindings.get(symbol, PointsToSet())

    def register_object(self, obj: AbstractObject) -> bool:
        """Register an abstract object. Returns False if budget exceeded."""
        if obj.object_id in self.object_store:
            return True
        if self.objects_allocated >= self.max_objects_per_function:
            self.is_truncated = True
            return False
        self.object_store[obj.object_id] = obj
        self.objects_allocated += 1
        return True

    def record_alias(self, binding: AliasBinding) -> None:
        """Record an alias evidence binding."""
        self.alias_evidence.append(binding)

    def copy_for_branch(self) -> "AliasEnvironment":
        """Create a shallow copy for branch analysis (if/else)."""
        return AliasEnvironment(
            bindings={k: v.copy() for k, v in self.bindings.items()},
            alias_evidence=list(self.alias_evidence),
            object_store=dict(self.object_store),
            objects_allocated=self.objects_allocated,
            max_objects_per_function=self.max_objects_per_function,
            max_points_to_candidates=self.max_points_to_candidates,
            is_truncated=self.is_truncated,
        )

    def merge_branch(self, other: "AliasEnvironment") -> "AliasEnvironment":
        """Deterministic lattice join of two branch environments."""
        merged_bindings: dict[str, PointsToSet] = {}
        all_keys = sorted(set(list(self.bindings.keys()) + list(other.bindings.keys())))
        for key in all_keys:
            lhs = self.bindings.get(key, PointsToSet())
            rhs = other.bindings.get(key, PointsToSet())
            merged_bindings[key] = lhs.merge(rhs, self.max_points_to_candidates)

        merged_store = dict(self.object_store)
        merged_store.update(other.object_store)

        merged_evidence = list(self.alias_evidence)
        seen = {(e.source_symbol, e.target_symbol, e.line) for e in merged_evidence}
        for e in other.alias_evidence:
            if (e.source_symbol, e.target_symbol, e.line) not in seen:
                merged_evidence.append(e)
                seen.add((e.source_symbol, e.target_symbol, e.line))

        return AliasEnvironment(
            bindings=merged_bindings,
            alias_evidence=merged_evidence,
            object_store=merged_store,
            objects_allocated=max(self.objects_allocated, other.objects_allocated),
            max_objects_per_function=self.max_objects_per_function,
            max_points_to_candidates=self.max_points_to_candidates,
            is_truncated=self.is_truncated or other.is_truncated,
        )
