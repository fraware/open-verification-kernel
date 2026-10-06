"""READ-ONLY six-surface Reaudit probe for PE peel closure tip 1.4.0.

Adjacent adapters beyond fortieth pins. Exit 0 = all PASS (no false authorize).
Non-material OOS shapes are documented separately and not asserted here.
"""

from __future__ import annotations

import sys

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority_unit
from tests.test_executed_expression_effect_closure import (
    _NINTH_EXEC,
    _assert_ninth_not_authorized,
    _helpers_source,
    _scope,
    _unit,
)

ex = _NINTH_EXEC
results: list[tuple[str, str]] = []


def _ok(surface: str) -> None:
    results.append((surface, "PASS"))


def _block(surface: str, detail: str) -> None:
    results.append((surface, f"BLOCK: {detail}"))


# --- CF ---
try:
    cf_imp = (
        "import types\nfrom functools import partial\n"
        "import operator\nimport builtins\n"
    )
    fn, vals = "list.append", '[partial(setattr, ns, "e")]'
    _assert_ninth_not_authorized(
        tuple(
            (c, cf_imp)
            for c in (
                f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
                f"d=dict({{k: vb.get(k) for k in vb}})\n"
                f'pm=partial(d["map"], {fn})\n'
                f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})",
                f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
                f"d={{}}\nfor k in sorted(vb):\n"
                f"    getattr(d, 'setdefault')(k, vb.get(k))\n"
                f'pm=partial(d["map"], {fn})\n'
                f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})",
                f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
                f"d={{}}\nfor k in iter(vb):\n    operator.ior(d, {{k: vb.get(k)}})\n"
                f'pm=partial(d["map"], {fn})\n'
                f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})",
            )
        )
    )
    _ok("cf")
except AssertionError as e:
    _block("cf", str(e)[:200])

# --- identity ---
try:
    id_imp = "import operator\nimport builtins\nfrom functools import partial\n"
    _assert_ninth_not_authorized(
        tuple(
            (body, id_imp)
            for body in (
                "g=operator.getitem([*zip([list.__dict__['sort']])],0)[0]"
                ".__get__(None, list)\nxs=[Mut]\ng(xs, key=type.__call__)",
                "xs=[*zip([list.__dict__['sort']])]; "
                "g=operator.getitem(xs,0)[0].__get__(None, list)\n"
                "ys=[Mut]\ng(ys, key=type.__call__)",
                "g=(0 or operator.getitem)([*zip([list.__dict__['sort']])],0)[0]"
                ".__get__(None, list)\nxs=[Mut]\ng(xs, key=type.__call__)",
                "g=list(filter(None, zip([list.__dict__['sort']])))[0][0]"
                ".__get__(None, list)\nxs=[Mut]\ng(xs, key=type.__call__)",
            )
        )
    )
    _ok("identity")
except AssertionError as e:
    _block("identity", str(e)[:200])

# --- lexical ---
try:
    lex_imp = (
        "import operator\nfrom functools import partial\n"
        "import copy\nimport builtins"
    )
    _assert_ninth_not_authorized(
        tuple(
            (
                f"d={{Mut:1}}\nnew=partial.__new__\n"
                f"e=({arm} and new)(partial, copy.copy, d)()\n"
                f"e|={{}}\nC,=e.keys()\nC()",
                lex_imp,
            )
            for arm in (
                "operator.itruediv(2,1)",
                'getattr(operator,"itruediv")(2,1)',
                "(0 or operator.itruediv)(2,1)",
                "[operator.itruediv][0](2,1)",
            )
        )
    )
    _ok("lexical")
except AssertionError as e:
    _block("lexical", str(e)[:200])

# --- alias ---
try:
    alias_cases = (
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\nfrom types import MappingProxyType\n"
        'g=getattr([partial(copy.copy)],"pop")\noc=operator.call\n'
        'c=oc(dict({"gi":operator.getitem})["gi"],[g.__call__],0)(*[0])(keys)\n'
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\nfrom types import MappingProxyType\n"
        'g=getattr([partial(copy.copy)],"pop")\noc=operator.call\n'
        'd={"gi":operator.getitem}\n'
        'c=oc(d["gi"],[g.__call__],0)(*[0])(keys)\n'
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\nfrom types import MappingProxyType\n"
        'g=getattr([partial(copy.copy)],"pop")\noc=operator.call\n'
        'ag=attrgetter("__call__")\n'
        "c=oc((0 or ag)(operator.getitem),[g.__call__],0)(*[0])(keys)\n"
        'c["z"]=c.pop("x"); k=c.get("z")\n'
        'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        "s.bypass_filter=bypass_filter",
    )
    for body in alias_cases:
        findings = _unit(
            "import helpers\nimport types, operator, copy\n"
            "from operator import methodcaller, attrgetter\n"
            "def evil(state, value):\n"
            "    state.bypass_filter = value\n"
            "def handler(request, bypass_filter=False):\n"
            "    request.state.bypass_filter = True\n"
            + "\n".join(f"    {ln}" for ln in body.split("\n"))
            + "\n    return request.state.bypass_filter"
        )
        if (
            findings[0].status == "authorized"
            or findings[0].reason == "source_proved_server_authority_write"
        ):
            raise AssertionError(body[:120])
    _ok("alias")
except AssertionError as e:
    _block("alias", str(e)[:200])

# --- class ---
try:
    class_imp = (
        "import types\nimport operator\nimport copy\n"
        "from functools import partial\nfrom collections import ChainMap\n"
        "from operator import iconcat, methodcaller"
    )
    _assert_ninth_not_authorized(
        tuple(
            (c, class_imp)
            for c in (
                f"ns=types.SimpleNamespace()\n"
                f"cm=ChainMap({{}}, vars(ns)); xs=[{{}}]; "
                f'iconcat(xs, list.copy(cm.maps)); xs[2]["e"]=exec\nns.e({ex})',
                f"ns=types.SimpleNamespace()\n"
                f"cm=ChainMap({{}}, vars(ns)); xs=[{{}}]; "
                f'(0 or iconcat)(xs, list.copy(cm.maps)); xs[2]["e"]=exec\n'
                f"ns.e({ex})",
                f"ns=types.SimpleNamespace()\n"
                f"cm=ChainMap({{}}, vars(ns)); xs=[{{}}]; "
                f'xs.extend(list.copy(cm.parents.maps)); xs[1]["e"]=exec\n'
                f"ns.e({ex})",
            )
        )
    )
    _ok("class")
except AssertionError as e:
    _block("class", str(e)[:200])

# --- interproc ---
try:
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
    for call in (
        "import json\n"
        "    from contextlib import nullcontext; args=(n.install,)\n"
        "    cm=nullcontext(*args); e=cm.__enter__; "
        "f=e(*json.JSONDecoder.decode(json.JSONDecoder(),'[]')); f(evil)",
        "from ast import literal_eval as le\n"
        "    from contextlib import nullcontext; args=(n.install,)\n"
        "    cm=nullcontext(*args); e=cm.__enter__; "
        "f=e(*le('[]')); f(evil)",
        "from contextlib import nullcontext; args=(n.install,)\n"
        "    from operator import methodcaller\n"
        "    cm=nullcontext(*args); e=cm.__enter__; "
        "xs=[]; f=e(*methodcaller('__iadd__',())(xs)); f(evil)",
        "import itertools as it\n"
        "    from contextlib import nullcontext; args=(n.install,)\n"
        "    cm=nullcontext(*args); e=cm.__enter__; "
        "f=e(*getattr(it.chain,'from_iterable')(())); f(evil)",
    ):
        routes = f"""
import pkg.nested as n
def evil(state, value):
    state.bypass_filter = value
def handler(request, bypass_filter=False):
    {call}
    n.write_state(request.state, bypass_filter)
    return request.state.bypass_filter
"""
        files = {
            "app/helpers.py": _helpers_source(),
            "app/pkg/__init__.py": "",
            "app/pkg/nested.py": nested,
            "app/routes.py": routes.strip(),
        }
        findings = analyze_bypass_authority_unit(
            files,
            entry_path="app/routes.py",
            function_name="handler",
            bypass_fields=frozenset({"bypass_filter"}),
            scope_proof=_scope(*files, import_roots=("app",)),
        )
        if (
            findings[0].status == "authorized"
            or findings[0].reason == "source_proved_server_authority_write"
        ):
            raise AssertionError(call[:120])
    _ok("interproc")
except AssertionError as e:
    _block("interproc", str(e)[:200])

for surface, status in results:
    print(f"{surface}: {status}")

blocked = [s for s, st in results if st != "PASS"]
sys.exit(1 if blocked else 0)
