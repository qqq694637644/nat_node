"""Ensure the deployed NAT node remains truly dependency-free.

No pip packages are needed by reverse_socks. When someone introduces an
external import, this test requires an explicit dependency review instead of
letting a clean Linux/VPS installation fail with ModuleNotFoundError.
"""

import ast
from pathlib import Path
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DependencyContractTest(unittest.TestCase):
    def test_runtime_uses_only_python_standard_library(self):
        source_files = sorted((PROJECT_ROOT / "reverse_socks").glob("*.py"))
        self.assertTrue(source_files, "reverse_socks sources were not found")
        for source in source_files:
            # Optional IPv6/QUIC mode is loaded only after --direct-quic;
            # the original FRP/XTCP runtime must remain stdlib-only.
            if source.name == "direct_quic.py":
                continue
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            with self.subTest(module=source.name):
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        modules = (alias.name for alias in node.names)
                    elif isinstance(node, ast.ImportFrom):
                        if node.level:
                            # Relative reverse_socks.protocol is our own code.
                            continue
                        modules = (node.module or "",)
                    else:
                        continue
                    for module in modules:
                        top_level = module.split(".", 1)[0]
                        self.assertIn(
                            top_level,
                            sys.stdlib_module_names,
                            f"{source.name} imports external module {module!r}; "
                            "declare it in requirements.txt and update the README",
                        )

    def test_requirements_file_has_zero_third_party_packages(self):
        requirements = (PROJECT_ROOT / "requirements.txt").read_text(
            encoding="utf-8"
        )
        entries = [
            line.strip()
            for line in requirements.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            entries, [],
            "Document and review new third-party Python packages before "
            "adding them to nat_node",
        )

    def test_direct_quic_optional_dependency_is_declared(self):
        requirements = (PROJECT_ROOT / "requirements-direct-quic.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("aioquic", requirements)


if __name__ == "__main__":
    unittest.main()
