from mitmproxy import http
import json
from datetime import datetime

class HARCapture:
    def __init__(self):
        self.flows = []
        self.har_file = "traffic.har"

    def request(self, flow: http.HTTPFlow):
        self.flows.append(flow)
        self.save()

    def response(self, flow: http.HTTPFlow):
        self.save()

    def save(self):
        entries = []
        for f in self.flows:
            req = f.request
            res = f.response

            started = datetime.fromtimestamp(req.timestamp_start).isoformat()
            duration = 0
            if res and res.timestamp_end:
                duration = (res.timestamp_end - req.timestamp_start) * 1000

            entry = {
                "startedDateTime": started,
                "time": duration,
                "request": {
                    "method": req.method,
                    "url": req.pretty_url,
                    "httpVersion": req.http_version,
                    "headers": [{"name": k, "value": v} for k, v in req.headers.items()],
                    "queryString": [{"name": k, "value": v} for k, v in req.query.items(multi=True)],
                    "postData": None
                },
                "response": {}
            }

            if req.content:
                entry["request"]["postData"] = {
                    "mimeType": req.headers.get("content-type", ""),
                    "text": req.get_text(strict=False)
                }

            if res:
                entry["response"] = {
                    "status": res.status_code,
                    "statusText": res.reason,
                    "httpVersion": res.http_version,
                    "headers": [{"name": k, "value": v} for k, v in res.headers.items()],
                    "content": {
                        "size": len(res.content or b""),
                        "mimeType": res.headers.get("content-type", ""),
                        "text": res.get_text(strict=False)
                    }
                }

            entries.append(entry)

        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "mitmproxy", "version": "1.0"},
                "entries": entries
            }
        }

        with open(self.har_file, "w") as f:
            json.dump(har, f, indent=2, ensure_ascii=False)

        print(f"[HAR] {len(entries)} flows saved")


class GPTInterceptor:
    def __init__(self):
        self.log_file = "gpt_conversations.log"
        self.conv_file = "conversations.txt"
        # only care about the main conversation endpoint for now
        self.endpoints = ["chatgpt.com/backend-api/f/conversation"]

    def is_gpt(self, url):
        return any(ep in url for ep in self.endpoints)

    def request(self, flow: http.HTTPFlow):
        if not self.is_gpt(flow.request.pretty_url):
            return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            data = json.loads(flow.request.content.decode("utf-8", errors="replace"))
            for msg in data.get("messages", []):
                if msg.get("author", {}).get("role") != "user":
                    continue
                parts = msg.get("content", {}).get("parts", [])
                prompt = "".join(p for p in parts if isinstance(p, str))
                if prompt:
                    with open(self.conv_file, "a") as f:
                        f.write(f"[{ts}] Prompt: {prompt}\n")
                    print(f"[{ts}] Prompt: {prompt}")
        except Exception as e:
            print(f"[req error] {e}")

    def response(self, flow: http.HTTPFlow):
        if not self.is_gpt(flow.request.pretty_url):
            return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = flow.response.status_code
        body = flow.response.content.decode("utf-8", errors="replace")

        resp_text = ""
        entries = []
        event = None
        collecting = False

        for line in body.splitlines():
            line = line.strip()
            if line.startswith("event:"):
                event = line[6:].strip()
                continue
            if not line.startswith("data:"):
                continue

            data_str = line[5:].strip()
            if data_str == "[DONE]":
                continue

            try:
                obj = json.loads(data_str)
            except:
                continue

            entries.append(obj)

            if event != "delta":
                continue

            # chatgpt streams the actual text as append ops on the first content part
            if obj.get("p") == "/message/content/parts/0" and obj.get("o") == "append":
                collecting = True
            if collecting and "v" in obj:
                resp_text += str(obj["v"])
            if obj.get("o") == "patch":
                collecting = False

        # dump full response objects for debugging
        with open(self.log_file, "a") as f:
            f.write(f"\n[{ts}] RESPONSE (Status: {status})\n")
            f.write("=" * 80 + "\n")
            for i, obj in enumerate(entries, 1):
                f.write(f"--- Entry #{i} ---\n")
                f.write(json.dumps(obj, indent=2, ensure_ascii=False) + "\n\n")
            f.write("=" * 80 + "\n\n")

        if resp_text:
            with open(self.conv_file, "a") as f:
                f.write(f"[{ts}] Assistant: {resp_text}\n")
            print(f"[{ts}] Assistant: {resp_text}")


addons = [HARCapture(), GPTInterceptor()]