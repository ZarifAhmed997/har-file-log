
import argparse
import sys
import os
import subprocess
from pathlib import Path


class HARProxyCLI:

    def __init__(self):
        self.addon_path = Path(__file__).parent / 'proxy.py'

    def run(self, args):

        if not self.addon_path.exists():
            print(f"Error: Addon file not found at {self.addon_path}")
            sys.exit(1)

        # Parse listen address
        try:
            host, port = args.listen.rsplit(':', 1)
            port = int(port)
        except ValueError:
            print("Error: Listen address must be in the format HOST:PORT")
            print("Example: 127.0.0.1:8080")
            sys.exit(1)

        # Set environment variables for addon configuration
        env = os.environ.copy()
        env['HAR_OUTPUT'] = args.output

        if args.domain:
            env['HAR_DOMAIN_FILTER'] = ','.join(args.domain)

        if args.verbose:
            env['HAR_VERBOSE'] = 'true'

        # Build mitmproxy command
        cmd = [
            'mitmproxy',
            '-s', str(self.addon_path),
            '--listen-host', host,
            '-p', str(port),
        ]

        # Print configuration
        print("Configuration:")
        print(f"  Listen: {host}:{port}")
        print(f"  Output: {args.output}")

        if args.domain:
            print(f"  Filter: {args.domain}")

        print(f"  Verbose: {'Yes' if args.verbose else 'No'}")
        print()

        # Print setup instructions
        print("Setup Instructions:")
        print(f"  1. Configure your client to use proxy: {host}:{port}")
        print("     For HTTPS, trust mitmproxy CA certificate")
        print("  2. Press Ctrl+C to stop and save HAR file")
        print()

        # Run mitmproxy
        process = None

        try:
            process = subprocess.Popen(cmd, env=env)
            process.wait()

        except KeyboardInterrupt:
            print("\n\nStopping proxy...")
            process.terminate()

            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

            print("Proxy stopped.")

        except FileNotFoundError:
            print("Error: 'mitmproxy' not found")
            print("Please install mitmproxy: pip install mitmproxy")
            sys.exit(1)

        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)


def main():
    """Main entry point."""

    parser = argparse.ArgumentParser(
        description="HAR Capture Proxy - Capture network traffic as HTTP Archive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python cli.py

  # Capture specific domain
  python cli.py -d example.com -o example.har
  
  # Capture multiple domains
  python cli.py -d example.com -d test.com -o traffic.har

  # Run on custom host and port with verbose logging
  python cli.py -l 127.0.0.1:9000 -o traffic.har -v

Setup for HTTPS:
  1. Copy CA certificate from ~/.mitmproxy/mitmproxy-ca-cert.pem
  2. Install as trusted certificate in your system/browser
  3. Configure client proxy to use mitmproxy
  4. HTTPS traffic will be captured in plain text
        """
    )

    parser.add_argument(
        '-o', '--output',
        default='traffic.har',
        help='Output HAR file path (default: capture.har)'
    )

    parser.add_argument(
        '-d', '--domain',
        action='append',
        default=None,
        help='Filter by domain (can be specified multiple times)'
    )

    parser.add_argument(
        '-l', '--listen',
        default='127.0.0.1:8080',
        help='Listen address in HOST:PORT format (default: 127.0.0.1:8080)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    cli = HARProxyCLI()
    cli.run(args)


if __name__ == '__main__':
    main()

