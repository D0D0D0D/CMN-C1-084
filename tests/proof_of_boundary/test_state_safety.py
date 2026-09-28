# PB-2 + PB-5: State Safety Verification
# Verifies that State contains only msgpack-safe types (no Pydantic, dataclass, JWT)

import ast
import os
import re
import pytest


CREDENTIAL_FIELD_PATTERNS = re.compile(
    r"(jwt|token|api_key|secret|password|credential|connection_string)", re.IGNORECASE
)

PROHIBITED_TYPE_ANNOTATIONS = [
    "BaseModel",
    "InvocationContext",
]


def _scan_state_file(filepath: str) -> list[str]:
    """Scan a state definition file for safety violations."""
    with open(filepath, "r") as f:
        source = f.read()
        tree = ast.parse(source, filename=filepath)

    violations = []

    for node in ast.walk(tree):
        # Check class definitions that look like State
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                    field_name = item.target.id

                    # Check for credential-like field names
                    if CREDENTIAL_FIELD_PATTERNS.search(field_name):
                        violations.append(
                            f"{filepath}:{item.lineno} — Credential-like field name: {field_name}"
                        )

                    # Check for prohibited type annotations
                    if item.annotation:
                        annotation_str = ast.dump(item.annotation)
                        for prohibited in PROHIBITED_TYPE_ANNOTATIONS:
                            if prohibited in annotation_str:
                                violations.append(
                                    f"{filepath}:{item.lineno} — Prohibited type in State: {prohibited}"
                                )

    return violations


class TestStateSafety:
    """PB-2/PB-5: State must be msgpack-safe with no credentials."""

    def test_state_file_safety(self):
        """State definition must not contain credential fields or prohibited types."""
        state_file = os.path.join(os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py")
        if not os.path.exists(state_file):
            pytest.skip("src/schemas/state.py not found")

        violations = _scan_state_file(state_file)

        assert violations == [], (
            f"State safety violations found:\n" + "\n".join(violations)
        )

    def test_state_fields_are_json_serializable_types(self):
        """PB-2: All State fields must use only JSON-serializable type annotations.

        Prohibited: datetime, bytes, date, time, Decimal, UUID.
        Allowed: str, int, float, bool, None, list, dict, Any
        """
        state_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py"
        )
        if not os.path.exists(state_file):
            pytest.skip("src/schemas/state.py not found")

        prohibited_types = {"datetime", "bytes", "date", "time", "Decimal", "UUID"}
        violations = []

        with open(state_file) as f:
            tree = ast.parse(f.read(), filename=state_file)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.AnnAssign):
                        annotation_str = ast.dump(item.annotation)
                        for prohibited in prohibited_types:
                            if prohibited in annotation_str:
                                field = (
                                    item.target.id
                                    if isinstance(item.target, ast.Name)
                                    else "unknown"
                                )
                                violations.append(
                                    f"Line {item.lineno} — field '{field}' uses "
                                    f"prohibited type '{prohibited}'"
                                )

        assert violations == [], (
            "Non-serializable type annotations found in state.py:\n"
            + "\n".join(violations)
        )

    def test_invocation_context_not_in_state(self):
        """PB-5: InvocationContext must not appear as a State field (Rule 1.3)."""
        state_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py"
        )
        if not os.path.exists(state_file):
            pytest.skip("src/schemas/state.py not found")

        with open(state_file) as f:
            source = f.read()

        tree = ast.parse(source)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.AnnAssign):
                        annotation_str = ast.dump(item.annotation)
                        if "InvocationContext" in annotation_str:
                            field = (
                                item.target.id
                                if isinstance(item.target, ast.Name)
                                else "unknown"
                            )
                            violations.append(
                                f"Line {item.lineno} — field '{field}' uses InvocationContext"
                            )

        assert violations == [], (
            "InvocationContext found as State field (Rule 1.3 violation):\n"
            + "\n".join(violations)
        )

    def test_state_inherits_from_agent_state(self):
        """PB-2: State class must inherit from AgentState (not BaseModel or TypedDict directly)."""
        state_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "schemas", "state.py"
        )
        if not os.path.exists(state_file):
            pytest.skip("src/schemas/state.py not found")

        with open(state_file) as f:
            tree = ast.parse(f.read())

        state_class = next(
            (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "State"),
            None,
        )
        assert state_class is not None, "State class not found in state.py"

        base_names = [
            base.id if isinstance(base, ast.Name) else
            base.attr if isinstance(base, ast.Attribute) else ""
            for base in state_class.bases
        ]
        assert "AgentState" in base_names, (
            f"State must inherit from AgentState, got bases: {base_names}"
        )
