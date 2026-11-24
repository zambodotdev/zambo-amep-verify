#!/usr/bin/env python3
"""Our own runner for the AMEP vectors/ suite. Drives every vector file
through amep_verify (in-process; the CLI contract is smoke-tested
separately) and writes results.json + disagreements.md."""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from amep_verify import run_packet_text, load_js_json, js_stringify, canon

REPO = os.environ.get("AMEP_REPO", os.path.join(os.path.dirname(os.path.abspath(__file__)), "amep"))
VECTORS = os.path.join(REPO, "vectors")


def main():
    with open(os.path.join(VECTORS, "keys.json"), encoding="utf-8") as fh:
        keyset = load_js_json(fh.read())
    keyset_sha = hashlib.sha256(canon(keyset)).hexdigest()
    files = []
    for sub in ("positive", "must-reject"):
        d = os.path.join(VECTORS, sub)
        for name in sorted(os.listdir(d)):
            if name.endswith(".json"):
                files.append((sub, name, os.path.join(d, name)))
    results = []
    disagreements = []
    suite_lines = []
    for sub, name, path in files:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        suite_lines.append("%s  %s/%s" % (hashlib.sha256(raw.encode("utf-8")).hexdigest(), sub, name))
        vec = load_js_json(raw)
        expect = vec.get("expect") or {}
        if "packet_text" in vec:
            packet_text = vec["packet_text"]
        else:
            packet_text = js_stringify(vec.get("packet"))
        verdict = run_packet_text(packet_text, keyset, vec.get("state"))
        got = {"outcome": verdict["outcome"], "invariant": verdict["invariant"]}
        ok = got["outcome"] == expect.get("outcome") and got["invariant"] == expect.get("invariant")
        record = {
            "vector": "%s/%s" % (sub, name[:-5]),
            "name": vec.get("name"),
            "expect": expect,
            "got": got,
            "pass": ok,
            "verdict_record": {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": "amep-packet",
                             "digest": {"sha256": hashlib.sha256(packet_text.encode("utf-8")).hexdigest()}}],
                "predicateType": "https://github.com/stafordtituss/amep/verdict/v0.3",
                "predicate": {
                    "packet": {"sha256": hashlib.sha256(packet_text.encode("utf-8")).hexdigest()},
                    "keyset": {"sha256": keyset_sha},
                    "verdict": {"outcome": verdict["outcome"],
                                "invariant": verdict["invariant"],
                                "blame": verdict["blame"], "gaps": verdict["gaps"]},
                    "results": [{k: r[k] for k in ("id", "outcome", "invariant", "blame", "gaps")}
                                for r in verdict["results"]],
                    "verifier": {"name": "zambo-amep-verify (independent, from spec text)",
                                 "version": "0.1.0"},
                },
            },
        }
        results.append(record)
        if not ok:
            disagreements.append({
                "vector": record["vector"],
                "expect": expect,
                "got": got,
                "results": [{k: r[k] for k in ("id", "outcome", "invariant", "reason")}
                            for r in verdict["results"]],
            })
    suite_sha = hashlib.sha256("\n".join(suite_lines).encode("utf-8")).hexdigest()
    npass = sum(1 for r in results if r["pass"])
    out = {
        "implementation": {"name": "zambo-amep-verify (independent, from spec text)",
                           "version": "0.1.0", "language": "Python (stdlib only)"},
        "suite": {"name": "vectors/", "files": len(results),
                  "sha256_of_file_hashes": suite_sha},
        "passed": npass,
        "failed": len(results) - npass,
        "positive": {"total": sum(1 for r in results if r["vector"].startswith("positive/")),
                     "passed": sum(1 for r in results if r["pass"] and r["vector"].startswith("positive/"))},
        "must_reject": {"total": sum(1 for r in results if r["vector"].startswith("must-reject/")),
                        "passed": sum(1 for r in results if r["pass"] and r["vector"].startswith("must-reject/"))},
        "with_state": sum(1 for r in results if False),
        "results": results,
        "disagreements": disagreements,
    }
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "results.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("TOTAL %d  PASS %d  FAIL %d" % (len(results), npass, len(results) - npass))
    print("positive: %d/%d   must-reject: %d/%d" % (
        out["positive"]["passed"], out["positive"]["total"],
        out["must_reject"]["passed"], out["must_reject"]["total"]))
    for d in disagreements:
        print("MISS %s expect %s got %s" % (d["vector"], d["expect"], d["got"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
