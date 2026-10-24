"""Regression guards for PySide6 panel/label backgrounds."""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEXT = (ROOT / "main.py").read_text(encoding="utf-8")
TREE = ast.parse(TEXT)
STYLE = next(ast.literal_eval(node.value)
             for node in TREE.body
             if isinstance(node, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "THEME" for t in node.targets))


class ThemeRules(unittest.TestCase):
    def test_not_all_widgets_paint_a_solid_background(self):
        self.assertNotRegex(STYLE, r"QWidget\s*\{[^}]*\bbackground\s*:")
        self.assertRegex(STYLE, r"QLabel\s*\{\s*background\s*:\s*transparent\s*;")
        self.assertIn("QWidget#pageSurface", STYLE)
        self.assertIn("QWidget#appRoot", STYLE)

    def test_all_pages_and_root_have_named_surfaces(self):
        self.assertEqual(TEXT.count("page.setObjectName('pageSurface')"), 5)
        self.assertIn("root.setObjectName('appRoot')", TEXT)
        self.assertIn("main.setObjectName('contentRoot')", TEXT)
        self.assertEqual(TEXT.count("QDialog { background:#172638; }"), 1)


if __name__ == "__main__":
    unittest.main()
