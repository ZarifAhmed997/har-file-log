from mitmproxy import http
import json
from datetime import datetime
import argparse

class HARCapture:
    def __init__(self, domains=None, har_file="traffic.har"):
        self.flows = []
        self.domains = domains if domains else []
        self.har_file = har_file

    def matches_domain(self, url):
        if not self.domains:
            return True
        return any(domain in url for domain in self.domains)
    
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        if self.matches_domain(url):
            self.flows.append(flow)
    
    def response(self, flow: http.HTTPFlow):
        self._update_har()
    
    def _update_har(self):
        entries = []
        for flow in self.flows:
            req = flow.request
            res = flow.response
            
            if not res:
                continue
            
            entry = {
                "startedDateTime": datetime.fromtimestamp(req.timestamp_start).isoformat(),
                "time": ((res.timestamp_end - req.timestamp_start) * 1000) if res.timestamp_end else 0,
                "request": {
                    "method": req.method,
                    "url": req.pretty_url,
                    "httpVersion": req.http_version,
                    "headers": [{"name": n, "value": v} for n, v in req.headers.items()],
                    "queryString": [{"name": n, "value": v} for n, v in req.query.items(multi=True)],
                    "postData": {"mimeType": req.headers.get("content-type", ""), "text": req.get_text(strict=False)} if req.content else None
                },
                "response": {
                    "status": res.status_code,
                    "statusText": res.reason,
                    "httpVersion": res.http_version,
                    "headers": [{"name": n, "value": v} for n, v in res.headers.items()],
                    "content": {
                        "size": len(res.content or b""),
                        "mimeType": res.headers.get("content-type", ""),
                        "text": res.get_text(strict=False)
                    }
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
        
        domain_info = f"all domains" if not self.domains else f"{', '.join(self.domains)}"
        print(f"[HAR] Captured {len(entries)} requests from {domain_info}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Capture HAR for specific domains")
    parser.add_argument("--domain", nargs="*", default=[], help="Domain(s) to capture (e.g., chatgpt.com api.example.com). Leave empty to capture all.")
    parser.add_argument("--output", default="traffic.har", help="Output HAR file")
    args = parser.parse_args()
    
    addons = [HARCapture(args.domain, args.output)]