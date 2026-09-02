
"""
HAR Capture Proxy - Capture network traffic as HTTP Archive (HAR) format
Uses mitmproxy to intercept all traffic (not just browser)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import os

from mitmproxy import ctx, http, options


class HARCapture:

    def __init__(self, output_path: str = "traffic.har", domain_filter: list = None, verbose: bool = False):
        """
        Args:
            output_path: Path to save HAR file
            domain_filter: Optional domain to filter (e.g., example.com)
            verbose: Whether to log detailed information
        """
        self.output_path = Path(output_path)
        self.domain_filter = domain_filter
        self.verbose = verbose
        # HAR structure
        self.entries: list[dict] = [] 
        self.start_time = datetime.now(timezone.utc)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        
        self.request_counter = 0
        self.total_size = 0

    def _should_capture(self, flow: http.HTTPFlow) -> bool:
        if not self.domain_filter:
            return True
        
        host = flow.request.host.lower()

        return any(host == domain or host.endswith('.' + domain) for domain in self.domain_filter)

    def _get_har_entry(self, flow: http.HTTPFlow) -> dict:
        """Convert mitmproxy flow to HAR entry format."""
        request = flow.request
        response = flow.response
        
        # Request headers
        request_headers = [
            {"name": name, "value": value}
            for name, value in request.headers.items()
        ]
        
        query_string = []
        if request.query:
            for key, value in request.query.items():
                query_string.append({
                    "name": key,
                    "value": value if value else ""
                })
        
        request_body_size = len(request.content) if request.content else 0

        request_body_text = ""

        if request.content:
            try:
                request_body_text = request.content.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                request_body_text = "[Binary Content]"
        
        response_headers = [
            {"name": name, "value": value}
            for name, value in response.headers.items()
        ]

        response_body_size = 0
        response_body_text = ""
        response_mime_type = "application/octet-stream"
        
        if response.content:
            response_body_size = len(response.content)
            content_type = response.headers.get("content-type", "application/octet-stream")
            response_mime_type = content_type.split(';')[0].strip()
            
            if any(mime in response_mime_type.lower() for mime in 
                   ['text', 'json', 'xml', 'javascript', 'application/x-www-form-urlencoded']):
                try:
                    response_body_text = response.content.decode('utf-8', errors='ignore')
                    # Limit text size in HAR to avoid huge files
                    if len(response_body_text) > 1000000:
                        response_body_text = response_body_text[:1000000] + "\n[Truncated - content too large]"
                except:
                    response_body_text = "[Binary Content]"
        
        # Timings (in milliseconds)
        
        timings = {}
        if hasattr(flow, 'start_time'):
            total_time = (flow.timestamp_end - flow.timestamp_start) * 1000 if hasattr(flow, 'timestamp_end') else 0
            
            # Rough estimation of timings
            timings = {
                "blocked": 0,
                "dns": 0,
                "connect": 0,
                "send": max(0, total_time * 0.1) if total_time else 0,
                "wait": max(0, total_time * 0.7) if total_time else 0,
                "receive": max(0, total_time * 0.2) if total_time else 0
            }
        
        total_time = sum(timings.values()) if timings else 0
        
        # Build HAR entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(
                flow.request.timestamp_start,
                tz=timezone.utc
            ).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
            "time": total_time,
            "request": {
                "method": request.method,
                "url": request.pretty_url,
                "httpVersion": f"HTTP/{request.http_version.decode() if isinstance(request.http_version, bytes) else request.http_version}",
                "headers": request_headers,
                "queryString": query_string,
                "headersSize": sum(len(f"{name}: {value}\r\n") for name, value in request.headers.items()),
                "bodySize": request_body_size
            },
            "response": {
                "status": response.status_code,
                "statusText": response.reason,
                "httpVersion": f"HTTP/{response.http_version.decode() if isinstance(response.http_version, bytes) else response.http_version}",
                "headers": response_headers,
                "content": {
                    "size": response_body_size,
                    "mimeType": response_mime_type,
                    "text": response_body_text if response_body_text else ""
                },
                "redirectURL": response.headers.get("location", ""),
                "headersSize": sum(len(f"{name}: {value}\r\n") for name, value in response.headers.items()),
                "bodySize": response_body_size
            },
            "cache": {},
            "timings": timings
        }
        
        return entry

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle HTTP response - add to HAR."""
        if not flow.response:
            return
        
        if not self._should_capture(flow):
            return
        
        try:
            entry = self._get_har_entry(flow)
            self.entries.append(entry)
            self.request_counter += 1
            
            if flow.response.content:
                self.total_size += len(flow.response.content)
            if flow.request.content:
                self.total_size += len(flow.request.content)
            
            # Log if verbose
            if self.verbose:
                self.logger.debug(
                    f"[{self.request_counter}] {flow.request.method} {flow.request.host} "
                    f"- {flow.response.status_code} ({len(flow.response.content) if flow.response.content else 0} bytes)"
                )
            else:
                # Print progress
                print(f"\rCaptured {self.request_counter} requests ({self._format_bytes(self.total_size)})", 
                      end='', flush=True)
        
        except Exception as e:
            self.logger.error(f"Error processing response: {e}")

    def error(self, flow: http.HTTPFlow) -> None:
        """Handle flow errors."""
        self.logger.warning(f"Error in flow {flow.request.url}: {flow.error}")

    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"

    def done(self) -> None:
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "HAR Capture Proxy",
                    "version": "1.0.0"
                },
                "browser": {
                    "name": "mitmproxy",
                    "version": "10.0.0"
                },
                "pages": [],
                "entries": self.entries
            }
        }
        
        # Write to file
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(har_data, f, indent=2, ensure_ascii=False)
        
        print(f"\nHAR file saved: {self.output_path.absolute()}")
        self._print_summary()

    def _print_summary(self) -> None:
        if not self.entries:
            print("No requests captured")
            return
        
        # Status codes
        status_codes: dict[int, int] = {}
        mime_types: dict[str, int] = {}
        total_response_size = 0
        
        for entry in self.entries:
            status = entry['response']['status']
            status_codes[status] = status_codes.get(status, 0) + 1
            
            mime = entry['response']['content']['mimeType']
            mime_types[mime] = mime_types.get(mime, 0) + 1
            
            total_response_size += entry['response']['content']['size']
        
        print("\n" + "="*50)
        print("Capture Summary")
        print("="*50)
        print(f"Total Requests: {len(self.entries)}")
        print(f"Total Data: {self._format_bytes(total_response_size)}")
        
        print(f"\nStatus Codes:")
        for status in sorted(status_codes.keys()):
            count = status_codes[status]
            icon = "✓" if 200 <= status < 300 else "→" if 300 <= status < 400 else "⚠️"
            print(f"  {icon} {status}: {count}")
        
        print(f"\nContent Types (top 10):")
        for mime, count in sorted(mime_types.items(), key=lambda x: x[1], reverse=True)[:10]:
            mime_short = mime.split('/')[-1] if '/' in mime else mime
            print(f"  • {mime_short}: {count}")
        
        print("="*50)

env = os.environ.copy() 
addons = [
    HARCapture(
        env.get("HAR_OUTPUT", "traffic.har"),
           env.get("HAR_DOMAIN_FILTER", "").split(',') if env.get("HAR_DOMAIN_FILTER") else None,
        True if env.get("HAR_VERBOSE", "false").lower() == "true" else False
    )
]