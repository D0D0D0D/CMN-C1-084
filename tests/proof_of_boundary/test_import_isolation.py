# PB-4: Import Isolation Verification
# Verifies that this template does not directly import Level 0 (agenticstar-platform SDK)

import ast
import os
import pytest


PROHIBITED_IMPORTS = [
    "agenticstar",
    "platform",  # AgentCore platform layer (not Python stdlib)
]

# Python stdlib 'platform' is allowed
STDLIB_PLATFORM_ALLOWED = True


def _scan_imports(filepath: str) -> list[str]:
    """Scan a Python file for prohibited imports using AST."""
    with open(filepath, "r") as f:
        tree = ast.parse(f.read(), filename=filepath)

    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prohibited in PROHIBITED_IMPORTS:
                    if alias.name == prohibited or alias.name.startswith(f"{prohibited}."):
                        if prohibited == "platform" and STDLIB_PLATFORM_ALLOWED:
                            # Skip Python stdlib platform
                            if alias.name == "platform":
                                continue
                        violations.append(f"{filepath}:{node.lineno} — import {alias.name}")

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for prohibited in PROHIBITED_IMPORTS:
                    if node.module == prohibited or node.module.startswith(f"{prohibited}."):
                        if prohibited == "platform" and STDLIB_PLATFORM_ALLOWED:
                            if node.module == "platform":
                                continue
                        violations.append(f"{filepath}:{node.lineno} — from {node.module} import ...")

    return violations


def _find_python_files(directory: str) -> list[str]:
    """Find all .py files under the given directory."""
    py_files = []
    for root, _dirs, files in os.walk(directory):
        for f in files:
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


class TestImportIsolation:
    """PB-4: Level 3 must not import Level 0."""

    def test_no_prohibited_imports_in_src(self):
        """All source files under src/ must not import agenticstar or platform."""
        src_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        violations = []
        for filepath in _find_python_files(src_dir):
            violations.extend(_scan_imports(filepath))

        assert violations == [], (
            f"Import Isolation violations found:\n" + "\n".join(violations)
        )

    def test_no_cross_template_imports_in_src(self):
        """PB-4: src/ must not import from other agent template packages (siblings)."""
        src_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        cross_template_patterns = ["agents.domain", "agents.base"]
        violations = []

        for filepath in _find_python_files(src_dir):
            with open(filepath) as f:
                tree = ast.parse(f.read(), filename=filepath)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for pattern in cross_template_patterns:
                        if node.module.startswith(pattern):
                            violations.append(
                                f"{filepath}:{node.lineno} — cross-template import: {node.module}"
                            )

        assert violations == [], (
            "Cross-template import violations found:\n" + "\n".join(violations)
        )

    def test_framework_imports_only_from_allowed_modules(self):
        """PB-4: src/ framework imports must only reference allowed L1 modules.

        Allowed: framework.graph, framework.nodes, framework.schemas,
                 framework.secrets, framework.errors, framework.llm,
                 framework.config, framework.state, framework.utils,
                 framework.security
        """
        src_dir = os.path.join(os.path.dirname(__file__), "..", "..", "src")
        if not os.path.exists(src_dir):
            pytest.skip("src/ directory not found")

        allowed_framework_prefixes = (
            "framework.graph",
            "framework.nodes",
            "framework.schemas",
            "framework.secrets",
            "framework.errors",
            "framework.llm",
            "framework.config",
            "framework.state",
            "framework.utils",
            "framework.security",
        )
        violations = []

        for filepath in _find_python_files(src_dir):
            with open(filepath) as f:
                tree = ast.parse(f.read(), filename=filepath)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    if node.module.startswith("framework.") and not node.module.startswith(
                        allowed_framework_prefixes
                    ):
                        violations.append(
                            f"{filepath}:{node.lineno} — unexpected framework module: {node.module}"
                        )

        assert violations == [], (
            "Unexpected framework module imports:\n" + "\n".join(violations)
        )
