"""Strongly-typed models for bounded conservative type inference and call contexts (Phase 16)."""

from enum import Enum
import hashlib
from typing import Optional
from pydantic import BaseModel, Field


class TypeConfidence(str, Enum):
    """Confidence level of inferred static type evidence."""
    KNOWN = "KNOWN"          # Direct syntactic constructor or resolved local type annotation
    LIKELY = "LIKELY"        # Single unambiguous return type or unique repo-local class match
    AMBIGUOUS = "AMBIGUOUS"  # Multiple candidate repo-local classes match method or union
    UNKNOWN = "UNKNOWN"      # Dynamic, unannotated, external, or unresolvable receiver


class TypeOrigin(str, Enum):
    """Source of static type inference evidence."""
    CONSTRUCTOR = "CONSTRUCTOR"              # x = UserRepository()
    TYPE_ANNOTATION = "TYPE_ANNOTATION"      # x: UserRepository = ...
    IMPORT_BINDING = "IMPORT_BINDING"        # from models import User
    RETURN_SIGNATURE = "RETURN_SIGNATURE"    # def get_repo() -> UserRepository:
    FACTORY_CALL = "FACTORY_CALL"            # repo = create_user_repo()
    SELF_RECEIVER = "SELF_RECEIVER"          # self.method() in ClassDef
    PARAMETER_BINDING = "PARAMETER_BINDING"  # db in def __init__(self, db: DatabaseClient)
    FIELD_ASSIGNMENT = "FIELD_ASSIGNMENT"    # self.db = db
    ALIAS = "ALIAS"                          # a = b
    UNRESOLVED = "UNRESOLVED"                # No static evidence available


class ConstantBool(str, Enum):
    """Bounded abstract domain for literal boolean control arguments."""
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class TypeBinding(BaseModel):
    """Inferred static type for a symbol, field, or expression."""
    type_name: str                           # Short name (e.g. "UserRepository")
    qualified_type_name: str                 # Full name (e.g. "app.repositories.UserRepository")
    confidence: TypeConfidence
    origin: TypeOrigin
    source_file: str
    line: int
    col: int = 0
    candidate_types: list[str] = Field(default_factory=list)  # Populated when AMBIGUOUS


class CallContext(BaseModel):
    """Bounded k-limiting call-string context representation (k <= 2)."""
    context_id: str                          # Deterministic 16-char SHA-256 hash or "ROOT"
    call_string: list[str] = Field(default_factory=list) # List of call-site IDs (max length k <= 2)
    argument_taint_mask: list[bool] = Field(default_factory=list) # arg_i is True if tainted
    constant_args: dict[int, ConstantBool] = Field(default_factory=dict) # param_i -> TRUE | FALSE
    receiver_type: Optional[str] = None      # Qualified receiver type if known
    depth: int = 0                           # Number of call sites in suffix (0 <= depth <= 2)

    @classmethod
    def create_root_context(cls) -> "CallContext":
        return cls(
            context_id="ROOT",
            call_string=[],
            argument_taint_mask=[],
            constant_args={},
            receiver_type=None,
            depth=0,
        )

    @classmethod
    def push_call_site(
        cls,
        parent: "CallContext",
        call_site_id: str,
        arg_taints: list[bool],
        constant_args: Optional[dict[int, ConstantBool]] = None,
        receiver_type: Optional[str] = None,
        max_k: int = 2,
    ) -> "CallContext":
        """Push a call-site onto the bounded call-string context suffix."""
        new_chain = (parent.call_string + [call_site_id])[-max_k:]
        const_dict = constant_args or {}
        sorted_consts = ",".join(f"{k}:{v.value}" for k, v in sorted(const_dict.items()))
        
        canonical_key = (
            f"{':'.join(new_chain)}|"
            f"{','.join(str(b) for b in arg_taints)}|"
            f"{sorted_consts}|"
            f"{receiver_type or ''}"
        )
        cid = hashlib.sha256(canonical_key.encode("utf-8")).hexdigest()[:16]
        return cls(
            context_id=cid,
            call_string=new_chain,
            argument_taint_mask=arg_taints,
            constant_args=const_dict,
            receiver_type=receiver_type,
            depth=len(new_chain),
        )


class TypeEnvironment(BaseModel):
    """Local type environment mapping symbol and field identifiers to inferred types."""
    bindings: dict[str, TypeBinding] = Field(default_factory=dict)
    # class_or_instance_var -> {field_name -> TypeBinding}
    field_bindings: dict[str, dict[str, TypeBinding]] = Field(default_factory=dict)

    def set_type(self, symbol_name: str, binding: TypeBinding) -> None:
        self.bindings[symbol_name] = binding

    def get_type(self, symbol_name: str) -> Optional[TypeBinding]:
        return self.bindings.get(symbol_name)

    def set_field_type(self, receiver_name: str, field_name: str, binding: TypeBinding) -> None:
        self.field_bindings.setdefault(receiver_name, {})[field_name] = binding

    def get_field_type(self, receiver_name: str, field_name: str) -> Optional[TypeBinding]:
        return self.field_bindings.get(receiver_name, {}).get(field_name)
