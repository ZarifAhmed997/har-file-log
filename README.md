# HAR Capture Proxy

Capture network traffic as HTTP Archive (HAR) format using mitmproxy. This tool intercepts all HTTP/HTTPS traffic from your applications and saves it in the standard HAR 1.2 format for analysis and debugging.

## Features

- **Complete Traffic Capture**: Intercepts all HTTP and HTTPS traffic (not just browser traffic)
- **HAR 1.2 Format**: Saves captures in the standard HTTP Archive format
- **Domain Filtering**: Optionally filter captures to specific domains
- **Detailed Metrics**: Captures request/response headers, bodies, status codes, timings, and content types
- **Summary Reports**: Generates capture statistics including status codes and content type breakdown
- **Verbose Logging**: Optional detailed logging for debugging

## Installation

### Prerequisites

- Python 3.7+
- mitmproxy 10.0.0 or compatible

### Setup

1. Install mitmproxy:
```bash
pip install mitmproxy
```

2. Clone or download this repository:
```bash
git clone https://github.com/ZarifAhmed997/har-file-log
```

## Quick Start

### Basic Usage

Start the proxy on the default address (127.0.0.1:8080):

```bash
python cli.py
```

Output will appear in `traffic.har`

### Capture Specific Domain

```bash
python cli.py -d example.com -o example.har
```

### Capture Multiple Domains

```bash
python cli.py -d example.com -d api.example.com -o traffic.har
```

### Custom Listen Address

```bash
python cli.py -l 0.0.0.0:9000 -o traffic.har
```

### Combined Example

```bash
python cli.py -l 127.0.0.1:8080 -d api.example.com -d cdn.example.com -o capture.har -v
```

## Configuration

### Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--output` | `-o` | `traffic.har` | Output HAR file path |
| `--domain` | `-d` | None | Filter by domain (can be specified multiple times) |
| `--listen` | `-l` | `127.0.0.1:8080` | Listen address in HOST:PORT format |
| `--verbose` | `-v` | False | Enable verbose logging |

## Setup Instructions

### Step 1: Configure Your Client

Configure your application or browser or system to use the proxy:

```
Host: 127.0.0.1
Port: 8080
```

**For HTTPS traffic**: You must trust the mitmproxy CA certificate

### Step 2: Install mitmproxy Certificate (for HTTPS)

1. Start the proxy at least once to generate certificates:
   ```bash
   python cli.py
   ```

2. Copy the CA certificate:
   ```bash
   # macOS/Linux
   cp ~/.mitmproxy/mitmproxy-ca-cert.pem /path/to/trusted/location
   ```

3. Install in your system or browser:

   **macOS:**
   ```bash
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
   ```

### Step 3: Capture Traffic

1. Start the proxy:
   ```bash
   python cli.py -o mytraffic.har
   ```

2. Use your application/browser with the proxy configured

3. Press `Ctrl+C` to stop and save the HAR file

4. The HAR file will be saved with a summary report

## Output Format

### HAR File Structure

The output HAR file includes:

- **HTTP Requests**: Method, URL, headers, query strings, body
- **HTTP Responses**: Status code, headers, content (text/binary), MIME type
- **Timings**: Request/response timing breakdown in milliseconds
- **Metadata**: Creator information, browser/proxy version
- **Statistics**: Generated in console output

### Example HAR Entry

```json
{
  "startedDateTime": "2024-01-15T10:30:45.123Z",
  "time": 250,
  "request": {
    "method": "GET",
    "url": "https://api.example.com/data",
    "httpVersion": "HTTP/1.1",
    "headers": [
      {"name": "User-Agent", "value": "Mozilla/5.0..."},
      {"name": "Accept", "value": "application/json"}
    ],
    "queryString": [
      {"name": "id", "value": "123"}
    ],
    "headersSize": 256,
    "bodySize": 0
  },
  "response": {
    "status": 200,
    "statusText": "OK",
    "httpVersion": "HTTP/1.1",
    "headers": [...],
    "content": {
      "size": 1024,
      "mimeType": "application/json",
      "text": "{...}"
    },
    "headersSize": 512,
    "bodySize": 1024
  },
  "cache": {},
  "timings": {
    "blocked": 0,
    "dns": 0,
    "connect": 0,
    "send": 25,
    "wait": 175,
    "receive": 50
  }
}
```

### Console Output Example

```
Captured 150 requests (12.5 MB)

==================================================
Capture Summary
==================================================
Total Requests: 150
Total Data: 12.5 MB

Status Codes:
  ✓ 200: 135
  → 301: 5
  ⚠️  404: 10

Content Types (top 10):
  • json: 45
  • javascript: 30
  • css: 15
  • png: 20
  • text: 25
  • woff2: 8
  • html: 2
==================================================
```

## Architecture

### Components

1. **proxy.py** - mitmproxy addon that:
   - Intercepts HTTP flows
   - Converts them to HAR entries
   - Handles request/response body decoding
   - Generates summary statistics
   - Writes final HAR file

2. **cli.py** - Command-line interface that:
   - Parses arguments
   - Manages mitmproxy process
   - Handles signals (Ctrl+C)
   - Sets environment variables

### How It Works

1. User runs `cli.py` with arguments
2. CLI starts mitmproxy with `proxy.py` addon
3. Addon intercepts each HTTP response
4. Response is converted to HAR entry format
5. Entry is stored in memory
6. On shutdown (Ctrl+C), HAR file is written
7. Summary statistics are printed

## Limitations

- **Response Body Truncation**: Text responses larger than 1MB are truncated to avoid huge HAR files
- **Binary Content**: Binary response bodies (images, videos, etc.) are not included, marked as `[Binary Content]`
- **Memory Usage**: All captured data is stored in memory. Very long captures may consume significant RAM
- **Text Encoding**: Only UTF-8 decodable text is captured. Binary data is marked as `[Binary Content]`
- **Timing Estimation**: Timing breakdown is estimated based on total request/response time

## Supported Content Types

The addon captures text for these MIME types:

- `text/*` (text/html, text/plain, text/css, etc.)
- `application/json`
- `application/xml`
- `application/javascript`
- `application/x-www-form-urlencoded`

All other content types are recorded as `[Binary Content]`

## Troubleshooting

### "mitmproxy not found"

Install mitmproxy:
```bash
pip install mitmproxy
```

### HTTPS traffic not captured

1. Verify mitmproxy certificate is installed in your system
2. Check that your application actually trusts the system certificate store
3. Restart the application after certificate installation
4. Try capturing HTTP traffic first to verify setup

### Large HAR file size

- Use domain filtering: `-d example.com`
- Capture for shorter duration
- Text responses over 1MB are automatically truncated

### Certificate trust errors

1. Regenerate certificates:
   ```bash
   rm -rf ~/.mitmproxy
   python cli.py  # Will recreate certificates
   ```
2. Re-import certificate into system/browser
3. Restart applications using the proxy

## Examples

### Example 1: Capture All Traffic

```bash
python cli.py -o full_capture.har
```

Captures all traffic on default port 8080.

### Example 2: Capture Single API

```bash
python cli.py -d api.github.com -o github.har
```

Captures only requests to api.github.com.

## References

- [HTTP Archive (HAR) Spec](http://www.softwareishard.com/blog/har-1-2-spec/)
- [mitmproxy Documentation](https://docs.mitmproxy.org/)
- [mitmproxy Addons](https://docs.mitmproxy.org/stable/addons-overview/)

## Environment Variables

For advanced usage, the addon reads these environment variables:

| Variable | Purpose |
|----------|---------|
| `HAR_OUTPUT` | HAR file output path |
| `HAR_DOMAIN_FILTER` | Comma-separated domains to filter (e.g., `example.com,api.example.com`) |
| `HAR_VERBOSE` | Enable verbose logging (`true`/`false`) |

These are automatically set by the CLI, but can be used for direct mitmproxy invocation.