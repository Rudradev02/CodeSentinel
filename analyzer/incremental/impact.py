"""Reverse dependency and call-graph impact analysis engine (Phase 21)."""

from collections import defaultdict
from typing import Any, Optional

from analyzer.dataflow.callgraph.models import FunctionDefinition
from analyzer.incremental.models import FunctionChangeKind, ImpactSet, InvalidationReason
from analyzer.models.parse import ImportCategory, ParsedFile


def compute_reverse_dependency_closure(
    changed_files: set[str],
    dependency_graph: dict[str, set[str]],
) -> set[str]:
    """Compute deterministic reverse transitive closure of dependent files.
    
    Args:
        changed_files: Set of directly modified/added/deleted normalized file paths.
        dependency_graph: Mapping of file_path -> set of file_paths it imports.
        
    Returns:
        Set of all files that directly or transitively depend on changed_files.
    """
    reverse_graph: dict[str, set[str]] = defaultdict(set)
    for importer, imported_set in dependency_graph.items():
        for imported in imported_set:
            if imported:
                reverse_graph[imported].add(importer)

    affected: set[str] = set(changed_files)
    queue: list[str] = sorted(list(changed_files))

    while queue:
        current = queue.pop(0)
        for dependent in sorted(reverse_graph.get(current, set())):
            if dependent not in affected:
                affected.add(dependent)
                queue.append(dependent)

    return affected


def classify_function_change(
    old_func: Optional[FunctionDefinition],
    new_func: Optional[FunctionDefinition],
    old_body_hash: Optional[str] = None,
    new_body_hash: Optional[str] = None,
) -> FunctionChangeKind:
    """Classify the semantic nature of a modification to a function."""
    if old_func is None or new_func is None:
        return FunctionChangeKind.UNKNOWN

    # Check signature change
    if len(old_func.parameters) != len(new_func.parameters):
        return FunctionChangeKind.SIGNATURE_CHANGED

    for p_old, p_new in zip(old_func.parameters, new_func.parameters):
        if p_old.name != p_new.name or p_old.type_hint != p_new.type_hint or p_old.has_default != p_new.has_default:
            return FunctionChangeKind.SIGNATURE_CHANGED

    # Check class inheritance / decorator / type information
    if old_func.decorators != new_func.decorators:
        return FunctionChangeKind.TYPE_INFORMATION_CHANGED

    if old_func.is_method != new_func.is_method or old_func.class_name != new_func.class_name:
        return FunctionChangeKind.INHERITANCE_CHANGED

    # If body hash is available, verify if body changed
    if old_body_hash and new_body_hash and old_body_hash != new_body_hash:
        return FunctionChangeKind.BODY_CHANGED_ONLY

    return FunctionChangeKind.BODY_CHANGED_ONLY


def build_impact_set(
    directly_changed: set[str],
    added_files: set[str],
    deleted_files: set[str],
    renamed_files: dict[str, str],
    all_discovered_files: set[str],
    dependency_graph: dict[str, set[str]],
    has_unresolved_dependencies: Optional[dict[str, bool]] = None,
) -> ImpactSet:
    """Construct canonical ImpactSet identifying affected, reusable, and invalidation reasons."""
    all_changed_seeds = set(directly_changed) | set(added_files) | set(deleted_files) | set(renamed_files.keys())

    # Compute reverse dependency closure
    affected_closure = compute_reverse_dependency_closure(all_changed_seeds, dependency_graph)

    # Conservative Unknown Rule: If a file has unresolved imports, conservatively invalidate its component directory
    if has_unresolved_dependencies:
        unresolved_components = set()
        for f, is_unresolved in has_unresolved_dependencies.items():
            if is_unresolved and f in all_changed_seeds:
                comp_dir = "/".join(f.split("/")[:-1])
                unresolved_components.add(comp_dir)

        if unresolved_components:
            for f in all_discovered_files:
                for comp in unresolved_components:
                    if comp and f.startswith(comp + "/"):
                        affected_closure.add(f)

    # Reusable files are discovered files not in affected closure
    reusable = set(all_discovered_files) - affected_closure

    # Map invalidation reasons
    reasons: dict[str, InvalidationReason] = {}
    for f in directly_changed:
        reasons[f] = InvalidationReason.DIRECT_SOURCE_CHANGE
    for f in added_files:
        reasons[f] = InvalidationReason.DIRECT_SOURCE_CHANGE
    for f in deleted_files:
        reasons[f] = InvalidationReason.DIRECT_SOURCE_CHANGE
    for old_f, new_f in renamed_files.items():
        reasons[old_f] = InvalidationReason.DIRECT_SOURCE_CHANGE
        reasons[new_f] = InvalidationReason.DIRECT_SOURCE_CHANGE

    for f in affected_closure:
        if f not in reasons:
            reasons[f] = InvalidationReason.DEPENDENCY_CHANGE

    return ImpactSet(
        directly_changed_files=directly_changed,
        affected_files=affected_closure,
        reusable_files=reusable,
        deleted_files=deleted_files,
        renamed_files=renamed_files,
        invalidation_reasons=reasons,
    )
