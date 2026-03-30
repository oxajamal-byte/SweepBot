import argparse
from sweepbot.threat_lookup import run_lookup
from sweepbot.log_parser import build_report
from sweepbot.utils import print_banner, print_summary, save_report, print_parse_summary, save_parse_report


def cmd_lookup(args):
    print_banner()
    print(f"  Querying threat intel for: {args.ip}\n")
    report = run_lookup(args.ip)
    print_summary(report)
    if not args.no_save:
        path = save_report(report)
        print(f"\n  Report saved to: {path}")


def cmd_parse(args):
    print_banner()
    print(f"  Parsing log file: {args.file}\n")
    try:
        report = build_report(args.file)
    except FileNotFoundError:
        print(f"  Error: file not found — {args.file}")
        return
    print_parse_summary(report)
    if args.output:
        path = save_parse_report(report, args.output)
        print(f"\n  Report saved to: {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="sweepbot",
        description="SweepBot — Modular Cybersecurity Toolkit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    lookup_parser = subparsers.add_parser(
        "lookup",
        help="Query threat intel APIs for an IP address",
    )
    lookup_parser.add_argument(
        "--ip",
        required=True,
        metavar="IP_ADDRESS",
        help="The IP address to investigate",
    )
    lookup_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Print results without saving a report file",
    )
    lookup_parser.set_defaults(func=cmd_lookup)

    parse_parser = subparsers.add_parser(
        "parse",
        help="Scan a log file for suspicious activity",
    )
    parse_parser.add_argument(
        "--file",
        required=True,
        metavar="LOG_FILE",
        help="Path to the log file to analyze",
    )
    parse_parser.add_argument(
        "--output",
        metavar="OUTPUT_FILE",
        help="Save the full report as JSON to this path",
    )
    parse_parser.set_defaults(func=cmd_parse)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
