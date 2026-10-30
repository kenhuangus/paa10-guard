"""The crosswalk to the Agentic Skills Top 10 and MCP Top 10 must stay complete and cite only rules that exist."""
import glob
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Crosswalk(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(ROOT, "crosswalk", "crosswalk.json"), encoding="utf8") as f:
            self.d = json.load(f)

    def test_every_item_present_once(self):
        self.assertEqual([i["id"] for i in self.d["agentic_skills"]], [f"AST{n:02d}" for n in range(1, 11)])
        self.assertEqual([i["id"] for i in self.d["mcp"]], [f"MCP{n:02d}" for n in range(1, 11)])

    def test_cited_rules_exist(self):
        src = ""
        for p in glob.glob(os.path.join(ROOT, "paa_guard", "*.py")):
            with open(p, encoding="utf8") as f:
                src += f.read()
        for it in self.d["agentic_skills"] + self.d["mcp"]:
            self.assertIn(it["coverage"], self.d["coverage_levels"])
            self.assertTrue(it["paa"], it["id"])
            for r in it["rules"]:
                self.assertIn(f'"{r}"', src, f"{it['id']} cites unknown rule {r}")


if __name__ == "__main__":
    unittest.main()
