#!/usr/bin/env python3
"""Retired historical Base transaction; not an alternative Outpost installer.

PRO-132 202bf01c / 36aa016a retain both Base installation paths while rejecting
the donor's compensation, private-key and predecessor-reactivation behavior.
Fresh Debian uses late-install.sh; existing Debian uses converge-existing.sh.
Both delegate their complete request to install-outpost.sh. This legacy
argument format lacks the required plan digest and source receipt and must
never be translated into an authorized request.

The original donor remains attributable in donor-comparison.json. Its callable
effects are intentionally absent here. Retirement is not installation proof.
"""


def main():
    raise SystemExit("RETIRED_BASE_ROAD_USE_CANONICAL_INSTALL_OUTPOST")


if __name__ == "__main__":
    main()
