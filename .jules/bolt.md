## 2024-05-24 - Precomputing tuples for str.endswith() in hot loops
**Learning:** While replacing `pathlib.Path().suffix` with `str.endswith(tuple(exts))` is a massive improvement, instantiating the tuple inside the inner loop of an `os.walk` adds unnecessary casting overhead. Precomputing the tuple outside the loop yields true O(C) matching without per-iteration casting penalties.
**Action:** When refactoring suffix/prefix matching in hot loops using `endswith`/`startswith`, always ensure any list-to-tuple casting happens before the loop begins.
