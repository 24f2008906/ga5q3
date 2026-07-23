from fastapi import FastAPI
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
import base64
import re

app = FastAPI()

WORKSPACE = Path("/home/agent/workspace").resolve()
HOME = Path("/home/agent").resolve()
SECRET = (HOME / ".netrc").resolve()
OUTBOX = Path("/data/agent/outbox").resolve()

ALLOWED_HOSTS = {
    "objects.githubusercontent.com",
    "pypi.org",
}


class ToolCall(BaseModel):
    tool: str
    command: str | None = None
    path: str | None = None
    content: str | None = None
    method: str | None = None
    url: str | None = None


def allow(reason="Allowed"):
    return {"decision": "allow", "reason": reason}


def block(reason="Blocked by policy"):
    return {"decision": "block", "reason": reason}


def normalize_path(path_str: str):
    path_str = path_str.replace("$HOME", str(HOME))
    path_str = path_str.replace("~", str(HOME))

    p = Path(path_str)

    if not p.is_absolute():
        p = WORKSPACE / p

    return p.resolve()


def contains_secret(command: str):
    if not command:
        return False

    cmd = command.replace("$HOME", str(HOME))
    cmd = cmd.replace("~", str(HOME))

    if str(SECRET) in cmd:
        return True

    # detect relative traversal
    paths = re.findall(r'(/[^\s;|&]+|(?:\.\.?/)+[^\s;|&]*)', cmd)

    for p in paths:
        try:
            if normalize_path(p) == SECRET:
                return True
        except Exception:
            pass

    # detect base64 encoded payloads
    for token in re.findall(r"[A-Za-z0-9+/=]{16,}", cmd):
        try:
            decoded = base64.b64decode(token).decode(errors="ignore")
            decoded = decoded.replace("$HOME", str(HOME))
            decoded = decoded.replace("~", str(HOME))
            if str(SECRET) in decoded:
                return True
        except Exception:
            pass

    return False


@app.post("/check")
def check(tool: ToolCall):

    # ---------------- BASH ----------------
    if tool.tool == "bash":
        if contains_secret(tool.command or ""):
            return block("Reading /home/agent/.netrc is forbidden.")

        return allow("Command permitted.")

    # ---------------- WRITE ----------------
    elif tool.tool == "write_file":
    if not tool.path:
        return block("Missing path.")

    try:
        p = tool.path.replace("$HOME", str(HOME)).replace("~", str(HOME))

        target = Path(p)

        if not target.is_absolute():
            target = OUTBOX / target

        target = target.resolve()

        if target == OUTBOX or OUTBOX in target.parents:
            return allow("Write inside outbox permitted.")

        return block("Writes allowed only inside /data/agent/outbox/")

    except Exception:
        return block("Invalid path.")

    # ---------------- HTTP ----------------
    elif tool.tool == "http_request":
        if not tool.url:
            return block("Missing URL.")

        host = urlparse(tool.url).hostname

        if host in ALLOWED_HOSTS:
            return allow("Approved host.")

        return block("Host not allowed.")

    return block("Unknown tool.")
