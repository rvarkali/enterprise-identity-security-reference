"""Local Compose deployment helper. Standard library only; no tuple writes."""
import fcntl
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[2]
STORE_NAME = "enterprise-iam-reference"
ID_PATTERN = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identifier(value):
    require(isinstance(value, str) and ID_PATTERN.fullmatch(value), "Invalid OpenFGA ID in response/configuration")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Api:
    def __init__(self, base):
        url = urllib.parse.urlsplit(base)
        require(url.scheme in ("http", "https") and url.hostname and not url.username
                and not url.password and not url.query and not url.fragment, "Invalid deployment API URL")
        self.base = base.rstrip("/")
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, body=None):
        # Mutation authority is never available over the ordinary HTTP URL.
        if body is not None and (path == "/stores" or path.endswith(("/write", "/authorization-models"))):
            require(self.base == "http://localhost:8082", "Mutation commands require the local Compose gateway URL")
            result = subprocess.run(["docker", "compose", "exec", "-T", "openfga",
                "python3", "-B", "/gateway/gateway.py", "write"], cwd=ROOT,
                input=json.dumps({"path": path, "body": body}), capture_output=True, text=True, timeout=35)
            require(result.returncode == 0, "Mutation gateway unavailable; no direct-write fallback")
            reply = json.loads(result.stdout)
            require(reply.get("status") in (200, 201), "Mutation rejected or recovery required")
            require(isinstance(reply.get("body"), dict), "Invalid mutation gateway response")
            return reply["body"]
        request = urllib.request.Request(self.base + path,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                require(response.status in (200, 201), "Unexpected OpenFGA response status")
                result = json.load(response)
            require(isinstance(result, dict), "Invalid OpenFGA response: expected JSON object")
            return result
        except urllib.error.HTTPError as error:
            raise ValueError(f"OpenFGA request failed: HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ValueError("OpenFGA unavailable or request timed out") from None
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid OpenFGA response: malformed JSON") from None

    def pages(self, path, field):
        token = ""
        seen = set()
        while True:
            page = self.request(path + "?" + urllib.parse.urlencode({"page_size": 100, "continuation_token": token}))
            require(isinstance(page.get(field), list), f"Invalid OpenFGA response: missing {field} list")
            for item in page[field]:
                require(isinstance(item, dict), "Invalid OpenFGA list entry")
                yield item
            token = page.get("continuation_token", "")
            require(isinstance(token, str) and token not in seen, "Invalid OpenFGA pagination token")
            if not token:
                break
            seen.add(token)


def canonical(model):
    """Ignore server ID and empty protobuf defaults; preserve all authorization fields."""
    require(isinstance(model, dict) and isinstance(model.get("type_definitions"), list)
            and isinstance(model.get("schema_version"), str), "Invalid authorization model response")
    def normalize(value):
        if isinstance(value, dict):
            # Empty 'this' and other userset expressions are significant; preserve them.
            defaults = {"metadata", "relations", "module", "source_info", "condition",
                        "object", "directly_related_user_types"}
            return {k: normalize(v) for k, v in value.items()
                    if not (k in defaults and v in (None, "", {}, []))}
        if isinstance(value, list):
            return sorted((normalize(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        return value
    body = {k: v for k, v in model.items() if k != "id"}
    if not body.get("conditions"):
        body.pop("conditions", None)
    for definition in body["type_definitions"]:
        require(isinstance(definition, dict) and isinstance(definition.get("type"), str), "Invalid type definition")
    return normalize(body)


def save_environment(path, values):
    require(not path.is_symlink(), "Refusing to replace a symlinked .env")
    lines = path.read_text().splitlines(keepends=True) if path.exists() else []
    keys = "|".join(re.escape(key) for key in values)
    pattern = re.compile(r"^\s*(?:export\s+)?(?:" + keys + r")\s*=")
    kept = "".join(line for line in lines if not pattern.match(line))
    if kept and not kept.endswith("\n"):
        kept += "\n"
    content = kept + "".join(f"{key}={value}\n" for key, value in values.items())
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=".env.", delete=False) as temp:
        temporary = Path(temp.name)
        try:
            os.chmod(temporary, 0o600)
            temp.write(content)
            temp.flush()
            os.fsync(temp.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)


def deploy(api, desired, env_path):
    expected = canonical(desired)
    require(desired.get("schema_version") == "1.1" and
            {d["type"] for d in desired["type_definitions"]} == {"user", "tenant", "project", "document"},
            "Expected schema 1.1 user, tenant, project and document types")
    stores = [s for s in api.pages("/stores", "stores") if s.get("name") == STORE_NAME]
    require(len(stores) <= 1, "Multiple dedicated stores found; resolve ambiguity manually (nothing deleted)")
    store = stores[0] if stores else api.request("/stores", {"name": STORE_NAME})
    store_id = identifier(store.get("id"))
    path = f"/stores/{store_id}/authorization-models"
    model_id = None
    for model in api.pages(path, "authorization_models"):
        if canonical(model) == expected:
            model_id = identifier(model.get("id"))
            break
    reused = model_id is not None
    if model_id is None:
        model_id = identifier(api.request(path, desired).get("authorization_model_id"))
    deployed = api.request(f"{path}/{model_id}").get("authorization_model")
    require(canonical(deployed) == expected, "Deployed model differs from local model")
    require(identifier(deployed.get("id")) == model_id, "Unexpected deployed model ID")
    result = api.request(f"/stores/{store_id}/check", {
        "authorization_model_id": model_id, "consistency": "HIGHER_CONSISTENCY",
        "tuple_key": {"user": f"user:{uuid.uuid4()}", "relation": "can_view", "object": f"project:{uuid.uuid4()}"}})
    require(type(result.get("allowed")) is bool, "Invalid Check response: expected boolean allowed")
    require(result["allowed"] is False, "Unexpected ALLOW for unprovisioned probe; configuration not saved")
    values = {"OPENFGA_API_URL": "http://openfga:8080", "OPENFGA_STORE_ID": store_id,
              "OPENFGA_AUTHORIZATION_MODEL_ID": model_id}
    # Exported shell variables override .env in Compose. Refuse conflicting values.
    for key, value in values.items():
        require(key not in os.environ or os.environ[key] == value,
                f"Conflicting exported {key}; unset it before deploying")
    save_environment(env_path, values)
    print(f"Store {'reused' if stores else 'created'}: {store_id}")
    print(f"Model {'reused' if reused else 'uploaded'}: {model_id}")
    print("Verified types and Check API: allowed=false")
    print("Saved OpenFGA variables in ignored .env; unrelated settings preserved.")
    print("Apply API environment: docker compose up -d --no-deps api")


def main():
    # Cross-process lock for deployments from this checkout, without persistent lock files.
    with open(__file__, "r") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another model deployment is running from this checkout") from None
        desired = json.loads(Path(sys.argv[1]).read_text())
        deploy(Api(os.environ.get("OPENFGA_DEPLOY_API_URL", "http://localhost:8082")), desired, ROOT / ".env")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
