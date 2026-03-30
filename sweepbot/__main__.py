import sys

# Ensure Unicode box-drawing and other non-ASCII chars render correctly on
# Windows terminals before colorama wraps stdout.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from sweepbot.main import main
main()
