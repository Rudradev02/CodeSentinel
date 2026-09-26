"""Tests for Phase 23 evidence-based authorization state extraction."""

import ast
import pytest
from analyzer.models.boundary import AuthorizationState, AuthenticationState
from analyzer.frameworks.flask import FlaskAdapter
from analyzer.frameworks.django import DjangoAdapter


def test_django_permission_required_decorator():
    adapter = DjangoAdapter()
    code = """
from django.contrib.auth.decorators import permission_required

@permission_required("app.can_delete_user")
def delete_user_view(request, user_id):
    return "deleted"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "delete_user_view")
    authz_state, required_perm = adapter.extract_authorization_state(func_node, "views.py")
    assert authz_state == AuthorizationState.PERMISSION_GRANTED
    assert required_perm == "app.can_delete_user"


def test_django_user_passes_test_decorator():
    adapter = DjangoAdapter()
    code = """
from django.contrib.auth.decorators import user_passes_test

@user_passes_test(lambda u: u.is_superuser)
def superuser_portal(request):
    return "admin"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "superuser_portal")
    authz_state, required_perm = adapter.extract_authorization_state(func_node, "views.py")
    assert authz_state == AuthorizationState.ROLE_VERIFIED


def test_authentication_does_not_imply_authorization():
    """Crucial Phase 23 requirement: Authentication does NOT imply Authorization."""
    adapter = DjangoAdapter()
    code = """
from django.contrib.auth.decorators import login_required

@login_required
def view_account(request):
    return "account"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "view_account")
    
    auth_state = adapter.extract_authentication_state(func_node, "views.py")
    authz_state, required_perm = adapter.extract_authorization_state(func_node, "views.py")

    assert auth_state == AuthenticationState.AUTHENTICATED
    assert authz_state == AuthorizationState.UNKNOWN
    assert required_perm is None


def test_misleading_variable_does_not_grant_authorization():
    """Variables like is_admin=True in function body must not trick static authorization analysis."""
    adapter = FlaskAdapter()
    code = """
from flask import Flask

app = Flask(__name__)

@app.route("/admin/delete")
def delete_all():
    is_admin = True
    role = "SUPERUSER"
    return "done"
"""
    tree = ast.parse(code)
    func_node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "delete_all")
    authz_state, required_perm = adapter.extract_authorization_state(func_node, "app.py")
    assert authz_state == AuthorizationState.UNKNOWN
    assert required_perm is None
