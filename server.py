import base64
import hmac
import json
import logging
import os
import threading
from flask import Flask, Response, jsonify, request, stream_with_context, abort
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
app = Flask(__name__)

# Public URL: https://YOUR_HOSTNAME/logs-viewer/
# Keep this prefix aligned with the Ingress path and rewrite-target.
URL_PREFIX = "/logs-viewer"
USERNAME = os.environ.get("UI_USERNAME", "admin")
PASSWORD = os.environ.get("UI_PASSWORD", "Welcome@123456")

try:
    config.load_incluster_config()
except config.ConfigException:
    config.load_kube_config()
core = client.CoreV1Api()

def authorized():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    try:
        user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        return hmac.compare_digest(user, USERNAME) and hmac.compare_digest(password, PASSWORD)
    except Exception:
        return False

@app.before_request
def require_auth():
    if request.path == "/healthz":
        return None
    if not PASSWORD or not authorized():
        return Response("Authentication required", 401,
                        {"WWW-Authenticate": 'Basic realm="Kubernetes Log Viewer"'})

@app.get("/healthz")
def healthz():
    return jsonify(status="ok")

@app.get(f"{URL_PREFIX}/")
@app.get(URL_PREFIX)
def index():
    with open("templates/index.html", encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html")

@app.get(f"{URL_PREFIX}/api/namespaces")
def namespaces():
    try:
        return jsonify([x.metadata.name for x in core.list_namespace().items])
    except ApiException as e:
        return jsonify(error=f"Kubernetes API error ({e.status}): {e.reason}"), 502

@app.get(f"{URL_PREFIX}/api/pods")
def pods():
    namespace = request.args.get("ns", "").strip()
    if not namespace:
        return jsonify(error="Missing ns parameter"), 400
    try:
        result = core.list_namespaced_pod(namespace)
        items = []
        for p in result.items:
            statuses = (p.status.container_statuses or []) if p.status else []
            ready = sum(1 for s in statuses if s.ready)
            containers = [c.name for c in (p.spec.containers or [])]
            init_containers = [c.name for c in (p.spec.init_containers or [])]
            items.append({
                "name": p.metadata.name,
                "phase": p.status.phase if p.status else "Unknown",
                "ready": f"{ready}/{len(containers)}",
                "containers": containers,
                "initContainers": init_containers,
            })
        return jsonify(items)
    except ApiException as e:
        return jsonify(error=f"Kubernetes API error ({e.status}): {e.reason}"), 502

@app.get(f"{URL_PREFIX}/api/logs")
def logs():
    namespace = request.args.get("ns", "").strip()
    pod = request.args.get("pod", "").strip()
    container = request.args.get("container", "").strip()
    previous = request.args.get("previous", "false").lower() == "true"
    try:
        lines = max(1, min(int(request.args.get("lines", "200")), 5000))
    except ValueError:
        return jsonify(error="lines must be a number"), 400
    if not namespace or not pod:
        return jsonify(error="ns and pod are required"), 400
    kwargs = {"name": pod, "namespace": namespace, "tail_lines": lines,
              "timestamps": True, "previous": previous}
    if container:
        kwargs["container"] = container
    try:
        output = core.read_namespaced_pod_log(**kwargs)
        return jsonify(logs=output or "No logs available")
    except ApiException as e:
        return jsonify(logs=f"Kubernetes API error ({e.status}): {e.reason}"), 502

@app.get(f"{URL_PREFIX}/api/logs/stream")
def stream_logs():
    namespace = request.args.get("ns", "").strip()
    pod = request.args.get("pod", "").strip()
    container = request.args.get("container", "").strip()
    if not namespace or not pod:
        return jsonify(error="ns and pod are required"), 400
    kwargs = {"name": pod, "namespace": namespace, "follow": True,
              "tail_lines": 100, "timestamps": True, "_preload_content": False}
    if container:
        kwargs["container"] = container

    def generate():
        response = None
        try:
            response = core.read_namespaced_pod_log(**kwargs)
            for raw in response.stream(amt=1024, decode_content=False):
                line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                for part in line.splitlines():
                    yield f"data: {json.dumps(part)}\n\n"
        except GeneratorExit:
            raise
        except Exception as e:
            yield f"data: {json.dumps('ERROR: ' + str(e))}\n\n"
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                             "Connection": "keep-alive"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
