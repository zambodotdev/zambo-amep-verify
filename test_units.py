import sys
sys.path.insert(0, "/home/hatch/workspace/.scratch/amep18-row1")
from amep_verify import canon, parse_strict

# RFC 8785 appendix B example (values from the RFC)
obj = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
       "string": "\u20ac$\u000f\nA'B\"\\\\\"/"}
want = (b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        b'"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
got = canon(obj)
assert got == want, (got, want)
print("JCS RFC8785 example OK")

# UTF-16 code-unit key ordering: U+10000 (surrogate pair D800 DC00) sorts
# BEFORE U+E000 in UTF-16 order, after it in code-point order.
obj2 = {"\ue000": 1, "\U00010000": 2}
got2 = canon(obj2)
want2 = b'{"\xf0\x90\x80\x80":2,"\xee\x80\x80":1}'
assert got2 == want2, (got2, want2)
print("JCS UTF-16 sort OK")

v, issues = parse_strict('{"a": 1, "a": 2}')
assert issues, "duplicate not caught"
v, issues = parse_strict('{"a": 9007199254740993}')
assert issues, "range not caught"
v, issues = parse_strict('{"a": 1200.0000000000000001}')
assert issues, "literal mismatch not caught"
v, issues = parse_strict('{"a": 0.1, "b": [1, 2.5, "x"]}')
assert not issues, issues
v, issues = parse_strict('{"a": "\\ud800"}')
assert issues, "lone surrogate not caught"
print("parse_strict OK")
