# Rule tests for python-security.yml (run with: semgrep --test rules/semgrep).
# A "ruleid" annotation means the named rule must match the next line;
# an "ok" annotation means it must not.
# Test-only code: never imported or executed.
import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    # ruleid: shipsafe.fastapi-input-to-shell, shipsafe.subprocess-shell-true
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ok: shipsafe.fastapi-input-to-shell, shipsafe.subprocess-shell-true
    subprocess.run(["ping", "-c", "1", host])


@app.post("/lookup")
async def lookup(name: str):
    # ruleid: shipsafe.fastapi-input-to-shell, shipsafe.os-system-non-literal
    os.system("nslookup " + name)


def not_a_route(cmd: str):
    # ok: shipsafe.fastapi-input-to-shell
    # ruleid: shipsafe.subprocess-shell-true
    subprocess.check_output(cmd, shell=True)
    # ok: shipsafe.os-system-non-literal
    os.system("uptime")


def yaml_cases(data: str):
    # ruleid: shipsafe.yaml-unsafe-load
    yaml.load(data)
    # ruleid: shipsafe.yaml-unsafe-load
    yaml.load(data, Loader=yaml.Loader)
    # ruleid: shipsafe.yaml-unsafe-load
    yaml.unsafe_load(data)
    # ok: shipsafe.yaml-unsafe-load
    yaml.load(data, Loader=yaml.SafeLoader)
    # ok: shipsafe.yaml-unsafe-load
    yaml.safe_load(data)


def eval_cases(expr: str):
    # ruleid: shipsafe.eval-exec-non-literal
    eval(expr)
    # ruleid: shipsafe.eval-exec-non-literal
    exec(expr)
    # ok: shipsafe.eval-exec-non-literal
    eval("1 + 1")


def sql_cases(cur, user_id: str):
    # ruleid: shipsafe.sql-string-formatting
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: shipsafe.sql-string-formatting
    cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
    # ruleid: shipsafe.sql-string-formatting
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    # ok: shipsafe.sql-string-formatting
    cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def misc_cases(blob: bytes, url: str):
    # ruleid: shipsafe.pickle-load
    pickle.loads(blob)
    # ruleid: shipsafe.requests-verify-false
    requests.get(url, verify=False)
    # ok: shipsafe.requests-verify-false
    requests.get(url, timeout=5)
    # ruleid: shipsafe.weak-hash
    hashlib.md5(blob)
    # ok: shipsafe.weak-hash
    hashlib.sha256(blob)


# ruleid: shipsafe.fastapi-cors-wildcard-credentials
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
# ok: shipsafe.fastapi-cors-wildcard-credentials
app.add_middleware(CORSMiddleware, allow_origins=["https://example.test"], allow_credentials=True)
