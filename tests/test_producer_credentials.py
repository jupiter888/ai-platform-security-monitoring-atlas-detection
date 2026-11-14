"""Private producer configuration and authenticated gateway publication."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.inference.api import publish_event
from src.telemetry.events import create_event
from src.telemetry.producer_credentials import load_producer_key


CONFIG = {
    "gateway": "a" * 64,
    "operator": "b" * 64,
    "fixture": "c" * 64,
}


class ProducerCredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.path = (
            self.root / ".config/project10/credentials/telemetry-producers.json"
        )
        self.path.parent.mkdir(parents=True)
        self.home = patch(
            "src.telemetry.producer_credentials.Path.home",
            return_value=self.root,
        )
        self.home.start()

    def tearDown(self):
        self.home.stop()
        self.directory.cleanup()

    def write(self, content=None):
        self.path.write_text(
            json.dumps(CONFIG) if content is None else content
        )
        self.path.chmod(0o600)

    def test_valid_configuration_returns_selected_role(self):
        self.write()
        for role, key in CONFIG.items():
            self.assertEqual(load_producer_key(role), key)

    def test_missing_configuration_fails_without_path_reflection(self):
        with self.assertRaises(RuntimeError) as caught:
            load_producer_key("gateway")
        self.assertNotIn(str(self.root), str(caught.exception))

    def test_group_or_world_readable_file_is_rejected(self):
        self.write()
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            load_producer_key("gateway")

    def test_symlink_is_rejected(self):
        target = self.root / "other.json"
        target.write_text(json.dumps(CONFIG))
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(RuntimeError):
            load_producer_key("gateway")

    def test_duplicate_fields_are_rejected(self):
        self.write(
            '{"gateway":"' + "a" * 64
            + '","gateway":"' + "d" * 64
            + '","operator":"' + "b" * 64
            + '","fixture":"' + "c" * 64 + '"}'
        )
        with self.assertRaises(RuntimeError):
            load_producer_key("gateway")

    def test_invalid_configuration_and_unknown_role_are_rejected(self):
        self.write('{"secret":"configuration-canary"}')
        with self.assertRaises(RuntimeError) as caught:
            load_producer_key("gateway")
        self.assertNotIn("configuration-canary", str(caught.exception))
        with self.assertRaises(RuntimeError):
            load_producer_key("unknown")

    def test_gateway_publisher_attaches_only_its_injected_key(self):
        event = create_event(
            provenance="synthetic",
            source="gateway",
            model="research-model",
            reason="authentication_failed",
        )
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.status = 202
        with patch(
            "src.inference.api.build_opener", return_value=opener
        ):
            self.assertTrue(publish_event(event, producer_key="a" * 64))
        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.get_header("Authorization"), "Bearer " + "a" * 64
        )
        self.assertEqual(request.data, event.to_json().encode())

if __name__ == "__main__":
    unittest.main()