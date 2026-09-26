"""Tests for Phase 23 trust boundary extraction across supported frameworks."""

import ast
import pytest
from analyzer.models.parse import ParsedFile, SymbolDefinition, SymbolKind
from analyzer.models.boundary import TrustBoundaryType, AuthenticationState, AuthorizationState
from analyzer.frameworks.flask import FlaskAdapter
from analyzer.frameworks.django import DjangoAdapter
from analyzer.frameworks.express import ExpressAdapter
from analyzer.frameworks.react import ReactAdapter
from analyzer.frameworks.base import FrameworkModelRegistry


def test_flask_adapter_route_and_params():
    adapter = FlaskAdapter()
    code = """
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/v1/users/<int:user_id>/posts/<slug>", methods=["GET", "POST"])
def get_user_posts(user_id, slug):
    query = request.args.get("q")
    data = request.json
    return "ok"
"""
    tree = ast.parse(code)
    pf = ParsedFile(
        file_path="app.py",
        relative_path="app.py",
        language="PYTHON",
        symbols=[
            SymbolDefinition(name="get_user_posts", kind=SymbolKind.FUNCTION, line_start=7, line_end=11)
        ],
        errors=[],
    )
    boundaries = adapter.extract_trust_boundaries(pf, ast_tree=tree, file_content=code)
    assert len(boundaries) == 4  # 2 path params + request.args + request.json
    
    # Path parameter boundaries
    path_param_symbols = {b.symbol_name for b in boundaries if b.boundary_type == TrustBoundaryType.HTTP_REQUEST_PARAM}
    assert "user_id" in path_param_symbols
    assert "slug" in path_param_symbols

    # Verify route pattern propagation onto path parameter boundaries
    param_b = next(b for b in boundaries if b.symbol_name == "user_id")
    assert param_b.framework == "FLASK"
    assert "GET" in (param_b.http_method or "")
    assert "POST" in (param_b.http_method or "")

    # Request data boundaries
    req_symbols = {b.symbol_name for b in boundaries}
    assert "request.args" in req_symbols
    assert "request.json" in req_symbols


def test_django_adapter_view_and_request_params():
    adapter = DjangoAdapter()
    code = """
from django.http import JsonResponse

def profile_view(request, account_id):
    search = request.GET.get('search')
    payload = request.body
    return JsonResponse({"status": "ok"})
"""
    tree = ast.parse(code)
    pf = ParsedFile(
        file_path="views.py",
        relative_path="views.py",
        language="PYTHON",
        symbols=[
            SymbolDefinition(name="profile_view", kind=SymbolKind.FUNCTION, line_start=4, line_end=7)
        ],
        errors=[],
    )
    boundaries = adapter.extract_trust_boundaries(pf, ast_tree=tree, file_content=code)
    assert len(boundaries) == 3
    symbols = {b.symbol_name for b in boundaries}
    assert "account_id" in symbols
    assert "request.GET" in symbols
    assert "request.body" in symbols
    assert all(b.framework == "DJANGO" for b in boundaries)


def test_express_adapter_route_and_params():
    adapter = ExpressAdapter()
    code = """
const express = require('express');
const app = express();

app.post('/api/items/:itemId/reviews', (req, res) => {
    const q = req.query.filter;
    const body = req.body;
    res.json({ success: true });
});
"""
    pf = ParsedFile(
        file_path="server.js",
        relative_path="server.js",
        language="JAVASCRIPT",
        symbols=[],
        errors=[],
    )
    boundaries = adapter.extract_trust_boundaries(pf, file_content=code)
    assert len(boundaries) == 2
    symbols = {b.symbol_name for b in boundaries}
    assert "req.query" in symbols
    assert "req.body" in symbols
    assert all(b.framework == "EXPRESS" for b in boundaries)


def test_react_adapter_client_boundary():
    adapter = ReactAdapter()
    code = """
import React from 'react';
import { useParams, useSearchParams } from 'react-router-dom';

export function UserProfile({ initialData }) {
    const { id } = useParams();
    const [searchParams] = useSearchParams();
    return <div>User {id}</div>;
}
"""
    pf = ParsedFile(
        file_path="UserProfile.jsx",
        relative_path="UserProfile.jsx",
        language="JAVASCRIPT",
        symbols=[
            SymbolDefinition(name="UserProfile", kind=SymbolKind.FUNCTION, line_start=5, line_end=9)
        ],
        errors=[],
    )
    boundaries = adapter.extract_trust_boundaries(pf, file_content=code)
    assert len(boundaries) == 2
    symbols = {b.symbol_name for b in boundaries}
    assert "useParams()" in symbols
    assert "useSearchParams()" in symbols
    assert all(b.framework == "REACT" for b in boundaries)


def test_framework_registry_loading():
    registry = FrameworkModelRegistry(load_defaults=True)
    adapters = registry.get_all_adapters()
    adapter_names = {a.framework_name.upper() for a in adapters}
    assert "FLASK" in adapter_names
    assert "DJANGO" in adapter_names
    assert "EXPRESS" in adapter_names
    assert "REACT" in adapter_names

    applicable = registry.get_applicable_adapters(["flask", "unknown_fw"])
    assert len(applicable) == 1
    assert applicable[0].framework_name == "FLASK"
