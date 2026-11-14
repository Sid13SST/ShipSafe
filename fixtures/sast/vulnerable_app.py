# DELIBERATELY VULNERABLE FIXTURE - DO NOT RUN, IMPORT, OR DEPLOY.
#
# Used only by scripts/verify_sast.sh to prove the SAST gate (Semgrep) FAILS
# on obvious, real vulnerability patterns. It is scanned as text and never
# executed: the guard below raises immediately if anything imports it.
# It targets nothing - there are no hosts, URLs, or credentials in it.
#
# Expected findings (rule id -> line pattern):
#   shipsafe.fastapi-input-to-shell     subprocess.run(f"ping ... {host}", shell=True)
#   shipsafe.subprocess-shell-true      same line
#   shipsafe.os-system-non-literal      os.system("cat " + filename)
#   shipsafe.yaml-unsafe-load           yaml.load(body)
#   shipsafe.eval-exec-non-literal      eval(expression)
#   shipsafe.sql-string-formatting      cur.execute(f"... {username} ...")
#   shipsafe.pickle-load                pickle.loads(blob)
raise RuntimeError("ShipSafe fixture: deliberately vulnerable, never import or run")

import os  # noqa: E402
import pickle  # noqa: E402
import sqlite3  # noqa: E402
import subprocess  # noqa: E402

import yaml  # noqa: E402
from fastapi import FastAPI  # noqa: E402

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    # Command injection: request input interpolated into a shell command.
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return {"out": out.stdout.decode()}


@app.get("/read")
def read(filename: str):
    # Command injection via os.system.
    return {"rc": os.system("cat " + filename)}


@app.post("/config")
def load_config(body: str):
    # Unsafe deserialisation: yaml.load without SafeLoader.
    return yaml.load(body)


@app.get("/calc")
def calc(expression: str):
    # Code injection: eval on request input.
    return {"result": eval(expression)}


@app.get("/user")
def user(username: str):
    # SQL injection: query built with an f-string.
    cur = sqlite3.connect(":memory:").cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchall()


@app.post("/restore")
def restore(blob: bytes):
    # Unsafe deserialisation: pickle on request body.
    return pickle.loads(blob)
