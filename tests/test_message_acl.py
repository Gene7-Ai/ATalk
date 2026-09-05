import json, tempfile, unittest
from pathlib import Path
from atalk.server import MessageAcl


class MessageACLTest(unittest.TestCase):
    def _acl(self, obj):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "acl.json"
        p.write_text(json.dumps(obj))
        return MessageAcl(str(p))

    def test_example_shape_restricts_as_documented(self):
        # This is exactly examples/message-acl.example.json.
        acl = self._acl({"restricted_peers": {"guest-agent": ["alice", "bob"]}})
        self.assertIsNone(acl.check("guest-agent", "alice"))
        self.assertIsNone(acl.check("guest-agent", "bob"))
        self.assertIsNotNone(acl.check("guest-agent", "eve"))
        self.assertIsNotNone(acl.check("guest-agent", "*"))
        # peers not listed remain unrestricted
        self.assertIsNone(acl.check("carol", "eve"))
        self.assertIsNone(acl.check("carol", "*"))

    def test_missing_file_is_unrestricted(self):
        acl = MessageAcl("/nonexistent/acl.json")
        self.assertIsNone(acl.check("anyone", "*"))


if __name__ == "__main__":
    unittest.main()
