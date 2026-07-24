# py-algorand-sdk

Drives `algosdk.encoding.is_ed25519_point` as a system under test.

To install dependencies:

```bash
pip install ./py-algorand-sdk
```

Installing from the submodule checkout means the harness tests the pinned
source rather than whatever release happens to be on the machine.

To run:

```bash
python3 main.py
```

Reads one hex-encoded input per line on stdin, writes one verdict per line on
stdout.
