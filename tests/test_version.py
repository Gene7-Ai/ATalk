import re, unittest
from pathlib import Path
import atalk


class VersionTest(unittest.TestCase):
    def test_source_version_matches_pyproject(self):
        txt = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', txt, re.M)
        self.assertIsNotNone(m)
        self.assertEqual(atalk.__version__, m.group(1))


if __name__ == "__main__":
    unittest.main()
