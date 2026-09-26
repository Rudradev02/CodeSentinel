"""Tests for Phase 23 evidence-based authentication state extraction."""

import ast
import pytest
from analyzer.models.boundary import AuthenticationState
from analyzer.frameworks.flask import FlaskAdapter
from analyzer.frameworks.django import DjangoAdapter
from analyzer.frameworks.express import ExpressAdapter


def test_flask_auth_decorator_detected():
    adapter = FlaskAdapter()
    code = """
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route("/dashboard")
@login_required
def dashboard():
    return "dashboard"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "dashboard")
    state = adapter.extract_authentication_state(func_node, "app.py")
    assert state == AuthenticationState.AUTHENTICATED


def test_flask_jwt_required_detected():
    adapter = FlaskAdapter()
    code = """
from flask import Flask
from flask_jwt_extended import jwt_required

app = Flask(__name__)

@app.route("/profile")
@jwt_required()
def profile():
    return "profile"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "profile")
    state = adapter.extract_authentication_state(func_node, "app.py")
    assert state == AuthenticationState.AUTHENTICATED


def test_django_login_required_detected():
    adapter = DjangoAdapter()
    code = """
from django.contrib.auth.decorators import login_required

@login_required
def secure_view(request):
    return "secure"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "secure_view")
    state = adapter.extract_authentication_state(func_node, "views.py")
    assert state == AuthenticationState.AUTHENTICATED


def test_misleading_function_name_remains_unknown():
    """Misleading function/variable names without structural decorator/check must NOT be inferred as authenticated."""
    adapter = FlaskAdapter()
    code = """
from flask import Flask

app = Flask(__name__)

@app.route("/bypass")
def authenticated_user_login_admin():
    # Looks like auth in name, but has no actual decorator
    return "open"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "authenticated_user_login_admin")
    state = adapter.extract_authentication_state(func_node, "app.py")
    assert state == AuthenticationState.UNKNOWN


def test_unauthenticated_public_endpoint():
    adapter = DjangoAdapter()
    code = """
def public_landing(request):
    return "public"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "public_landing")
    state = adapter.extract_authentication_state(func_node, "views.py")
    assert state == AuthenticationState.UNKNOWN
