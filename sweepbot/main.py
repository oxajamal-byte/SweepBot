import argparse
from sweepbot.threat_lookup import run_lookup
from sweepbot.utils import print_banner, print_summary, save_report


def cmd_lookup(args):
    print_banner()
    print(f"  Querying threat intel for: {args.ip}\n")
    report = run_lookup(args.ip)
    print_summary(report)
    if not args.no_save:
        path = save_report(report)
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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
