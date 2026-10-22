import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error
import deploy


class DeploymentTests(unittest.TestCase):
    def test_comparison_preserves_authorization_and_ignores_server_defaults(self):
        local = {"schema_version": "1.1", "type_definitions": [
            {"type": "user"}, {"type": "tenant", "relations": {"member": {"this": {}}}}]}
        server = copy.deepcopy(local)
        server.update(id="server-id", conditions={})
        server["type_definitions"][0].update(metadata=None, relations={})
        server["type_definitions"].reverse()
        self.assertEqual(deploy.canonical(local), deploy.canonical(server))
        server["type_definitions"][0]["relations"]["member"] = {"computedUserset": {"relation": "admin"}}
        self.assertNotEqual(deploy.canonical(local), deploy.canonical(server))

    def test_env_updates_only_owned_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("# keep\nUNRELATED=preserved\nOPENFGA_STORE_ID=old\n")
            deploy.save_environment(path, {"OPENFGA_STORE_ID": "new"})
            deploy.save_environment(path, {"OPENFGA_STORE_ID": "new"})
            self.assertEqual(path.read_text(), "# keep\nUNRELATED=preserved\nOPENFGA_STORE_ID=new\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_invalid_json_and_unavailable_fail_clearly(self):
        api = deploy.Api("http://localhost:8082")
        with patch.object(api.opener, "open", side_effect=urllib.error.URLError("private details")):
            with self.assertRaisesRegex(ValueError, "unavailable"):
                api.request("/stores")
        for body in (b"not JSON", b"[]"):
            response = io.BytesIO(body)
            response.status = 200
            with patch.object(api.opener, "open", return_value=response):
                with self.assertRaisesRegex(ValueError, "Invalid OpenFGA response"):
                    api.request("/stores")

    def test_pagination_and_invalid_lists(self):
        api = deploy.Api("http://localhost:8082")
        with patch.object(api, "request", side_effect=[
            {"stores": [{"name": "other"}], "continuation_token": "next"},
            {"stores": [{"name": deploy.STORE_NAME}], "continuation_token": ""}]):
            self.assertEqual(len(list(api.pages("/stores", "stores"))), 2)
        with patch.object(api, "request", return_value={"error": "invalid"}):
            with self.assertRaisesRegex(ValueError, "missing stores list"):
                list(api.pages("/stores", "stores"))


if __name__ == "__main__":
    unittest.main()
