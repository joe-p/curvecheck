"""Persistent differential SUT for py-algorand-sdk.

Reads one hex-encoded input per line from stdin, writes one verdict
("true"/"false") per line to stdout. Started once by the Go harness and fed
every test input over the same process, so interpreter startup is paid a
single time rather than per input.

An input is not necessarily 32 bytes: the harness also exercises the length
guard, and an empty line means the empty input. Every line read must produce
exactly one verdict line, or the harness and this process fall out of step.
"""

import sys

from algosdk.encoding import is_ed25519_point


def main() -> None:
    out = sys.stdout
    for line in sys.stdin:
        raw = bytes.fromhex(line.strip())
        out.write("true\n" if is_ed25519_point(raw) else "false\n")
        # The harness blocks on this reply before sending the next input, so
        # the verdict has to leave the buffer now rather than at exit.
        out.flush()


if __name__ == "__main__":
    main()
