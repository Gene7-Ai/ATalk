import tempfile, unittest
from pathlib import Path
from atalk.server import MessageAcl


class AclFailClosedTest(unittest.TestCase):
    def test_broken_config_on_first_load_denies_all(self):
        d = tempfile.TemporaryDirectory(); self.addCleanup(d.cleanup)
        p = Path(d.name) / "acl.json"
        p.write_text("{not-json")
        acl = MessageAcl(str(p))
        # a present-but-unparseable file must fail closed, not allow everything
        self.assertIsNotNone(acl.check("guest-agent", "*"))
        self.assertIsNotNone(acl.check("anyone", "bob"))

    def test_absent_file_is_unrestricted(self):
        acl = MessageAcl("/nonexistent/acl.json")
        self.assertIsNone(acl.check("anyone", "*"))


if __name__ == "__main__":
    unittest.main()
