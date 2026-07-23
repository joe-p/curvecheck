import { couldBeCurvePoint } from './js-algorand-sdk/src/utils/ed25519-check.ts'

// Persistent differential SUT: read one hex-encoded input per line from stdin,
// write one verdict ("true"/"false") per line to stdout. Started once by the Go
// harness and fed every test input over the same process, so bun startup is
// paid a single time rather than per input.

function verdict(hex: string): boolean {
  return couldBeCurvePoint(Buffer.from(hex, 'hex'));
}

const decoder = new TextDecoder();
let buf = '';

function handle(line: string) {
  process.stdout.write(verdict(line.trim()) ? 'true\n' : 'false\n');
}

for await (const chunk of Bun.stdin.stream()) {
  buf += decoder.decode(chunk, { stream: true });
  let nl: number;
  while ((nl = buf.indexOf('\n')) !== -1) {
    handle(buf.slice(0, nl));
    buf = buf.slice(nl + 1);
  }
}
// Flush a trailing line that had no newline terminator.
if (buf.length > 0) handle(buf);
