from mitmproxy import http
import json
from datetime import datetime

class HARCapture:
    def __init__(self):
        self.flows = []
        self.har_file = "traffic.har"
    
    def request(self, flow: http.HTTPFlow):
        self.flows.append(flow)
        self._update_har()
    
    def response(self, flow: http.HTTPFlow):
        self._update_har()
    
    def _update_har(self):
        entries = []
        
        for flow in self.flows:
            request = flow.request
            response = flow.response
            
            entry = {
                "startedDateTime": datetime.fromtimestamp(
                    request.timestamp_start
                ).isoformat(),
                "time": (
                    (response.timestamp_end - request.timestamp_start) * 1000
                    if response and response.timestamp_end
                    else 0
                ),
                "request": {
                    "method": request.method,
                    "url": request.pretty_url,
                    "httpVersion": request.http_version,
                    "headers": [
                        {"name": name, "value": value}
                        for name, value in request.headers.items()
                    ],
                    "queryString": [
                        {"name": name, "value": value}
                        for name, value in request.query.items(multi=True)
                    ],
                    "postData": (
                        {
                            "mimeType": request.headers.get("content-type", ""),
                            "text": request.get_text(strict=False)
                        }
                        if request.content
                        else None
                    )
                },
                "response": (
                    {
                        "status": response.status_code,
                        "statusText": response.reason,
                        "httpVersion": response.http_version,
                        "headers": [
                            {"name": name, "value": value}
                            for name, value in response.headers.items()
                        ],
                        "content": {
                            "size": len(response.content or b""),
                            "mimeType": response.headers.get("content-type", ""),
                            "text": response.get_text(strict=False)
                        }
                    }
                    if response
                    else {}
                )
            }
            
            entries.append(entry)
        
        har = {
            "log": {
                "version": "1.2",
                "creator": {"name": "mitmproxy", "version": "1.0"},
                "entries": entries
            }
        }
        
        with open(self.har_file, "w", encoding="utf-8") as f:
            json.dump(har, f, indent=2, ensure_ascii=False)
        
        print(f"[HAR] Updated: {len(entries)} flows captured")
    
    def done(self):
        pass

class GPTInterceptor:
    def __init__(self):
        self.log_file = "gpt_conversations.log"
        self.conversation_file = "conversations.txt"
        self.gpt_endpoints = [
            "chatgpt.com/backend-api/f/conversation"
        ]
    
    def is_request(self, url):
        return any(endpoint in url for endpoint in self.gpt_endpoints)

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url

        if not self.is_request(url):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            body = flow.request.content.decode("utf-8", errors="replace")
            parsed = json.loads(body)

            for message in parsed.get("messages", []):
                if message.get("author", {}).get("role") != "user":
                    continue

                parts = message.get("content", {}).get("parts", [])

                prompt = "".join(
                    part for part in parts
                    if isinstance(part, str)
                )

                if prompt:
                    with open(self.conversation_file, "a", encoding="utf-8") as f:
                        f.write(f"[{timestamp}] Prompt: {prompt}\n")

                    print(f"[{timestamp}] Prompt: {prompt}")

        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse request JSON: {e}")

    
    def response(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url

        if not self.is_request(url):
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        status = flow.response.status_code

        body = flow.response.content.decode("utf-8", errors="replace")

        assistant_response = ""
        matches = []

        current_event = None
        collecting_text = False

        for line in body.splitlines():

            line = line.strip()

            if line.startswith("event:"):
                current_event = line[6:].strip()
                continue

            if not line.startswith("data:"):
                continue

            data_str = line[5:].strip()

            if data_str == "[DONE]":
                continue

            try:
                parsed = json.loads(data_str)
            except json.JSONDecodeError:
                print(f"[ERROR] Failed to parse: {data_str[:200]}")
                continue

            matches.append(parsed)

            if not isinstance(parsed, dict):
                continue

            # We only care about delta events
            if current_event != "delta":
                continue

            if (
                parsed.get("p") == "/message/content/parts/0"
                and parsed.get("o") == "append"
            ):
                collecting_text = True

            if collecting_text:
                value = parsed.get("v")

                if isinstance(value, str):
                    assistant_response += value

            if parsed.get("o") == "patch":
                collecting_text = False

        with open(self.log_file, "a", encoding="utf-8") as f:

            f.write(f"\n[{timestamp}] RESPONSE (Status: {status})\n")
            f.write("=" * 80 + "\n\n")

            for i, parsed in enumerate(matches, 1):

                f.write(f"--- Data Entry #{i} ---\n")

                f.write(
                    json.dumps(
                        parsed,
                        indent=4,
                        ensure_ascii=False
                    )
                )

                f.write("\n\n")

            f.write("=" * 80 + "\n\n")

        if assistant_response:

            with open(self.conversation_file, "a", encoding="utf-8") as f:

                f.write(
                    f"[{timestamp}] Assistant: {assistant_response}\n"
                )

            print(
                f"[{timestamp}] Assistant: {assistant_response}"
            )

        else:

            print(
                f"[{timestamp}] No assistant response extracted"
            )

addons = [HARCapture(), GPTInterceptor()]