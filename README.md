# zambo-amep-verify

An independent implementation of the AMEP evaluation procedure, written by
Brennan Zambo (Zambo, zambo.dev) from the specification text and the
published conformance vectors alone, without reading either of AMEP's
reference verifiers (Python or JavaScript). Nothing from the AMEP
repository was executed; everything here is original code written against
`spec/amep-v0.2.md` and the `vectors/` suite of
[stafordtituss/amep](https://github.com/stafordtituss/amep).

## What is implemented

- Section 12.2 signature acceptance, with a pure-Python Ed25519 verifier
  written from RFC 8032 (stdlib only: no PyNaCl, no cryptography module).
- RFC 8785 (JCS) canonicalization, from the RFC rules as restated in
  spec Section 12.1.
- The Section 15.1 strict parser.
- Single-packet evaluation, Sections 10.1 to 10.8, emitting a Section
  10.8 verdict record per vector.
- The conformance CLI shape from AMEP's `packages/conformance` README:
  a packet file and a key set go in, `{"outcome": ..., "invariant": ...}`
  comes out.

Not yet implemented: cross-packet state building (Section 10.7) and the
two interop suites. Those are the next rows, as scoped in the
implementation report.

## Results

Against the core suite (`vectors/`, 246 files), suite pinned first at
stafordtituss/amep main `5f1700c` and re-run unchanged at `59d0daf` (the
commit that records this implementation in spec 15.2; the vector files
are byte-identical between the two pins, suite digest
sha256:2bfa95fa538395e89da63c1667a2fe540c36109f56e433393fe59da64e979a43):

- First row, per the scoping in stafordtituss/amep#18: **228 of 228**
  single-packet vectors agree with the published expectation, in outcome
  and in deciding invariant (60 positive preserved, 168 must-reject).
- The 18 state-carrying vectors are out of the first row's scope. With
  state consumed exactly as those vectors supply it, they also agree
  18 of 18, taking the full core suite to 246 of 246.
- Disagreements with the published expectations: none.

The full per-vector results are in `results.json` (a Section 10.8
verdict record per vector, produced by `run_suite.py`).

Four readings the first pass got wrong were all on this side of the
table, and each was fixed before the results were reported: the
Section 7.3 meet fold direction, the Section 7.6 rule 5 period-total
anchor, Section 5.10 single-digest approval covering exactly one
execution, and Section 5.9's observerless receipt. The AMEP spec text
now states each of the four points (commit `59d0daf`).

## Files

- `amep_verify.py` — the verifier and CLI.
- `run_suite.py` — the runner: drives every vector file under a local
  AMEP checkout's `vectors/` directory and writes `results.json`.
- `test_units.py` — unit checks for the Ed25519 verifier (RFC 8032 test
  vector 1) and the JCS canonicalizer (RFC 8785 Appendix B).
- `results.json` — the per-vector results of record.

## The report of record

Filed on stafordtituss/amep as an implementation report from its own
template, and announced in
[stafordtituss/amep#18](https://github.com/stafordtituss/amep/issues/18).
AMEP's spec 15.2 and LIMITS.md record this implementation there.
