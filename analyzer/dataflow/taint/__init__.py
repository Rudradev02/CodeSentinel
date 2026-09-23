"""Taint models, declarative rules catalog, and intraprocedural taint propagator."""

from analyzer.dataflow.taint.models import (
    SinkCategory,
    SourceCategory,
    TaintPath,
    TaintSanitizer,
    TaintSink,
    TaintSource,
    TaintState,
    TaintStep,
)
from analyzer.dataflow.taint.registry import TaintRegistry

__all__ = [
    "SinkCategory",
    "SourceCategory",
    "TaintPath",
    "TaintSanitizer",
    "TaintSink",
    "TaintSource",
    "TaintState",
    "TaintStep",
    "TaintRegistry",
]
