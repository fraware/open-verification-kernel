"""Peel adapter matrix: six-family × catalog adapters (fast core).

Asserts never ``authorized`` + ``source_proved_server_authority_write`` when
Mut / evil is reachable through composed peel adapters. Positive inert
counterparts remain authorized where today's smokes do.
"""

from __future__ import annotations

import pytest

from ovk.compilers.authorization.bypass_authority import analyze_bypass_authority_unit
from ovk.compilers.authorization.persistent_fastapi_state import (
    PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION,
)
from tests.pe_peel_catalog import FAST_CORE_ADAPTERS, FAMILY_HEADS, wrap_adapter
from tests.test_executed_expression_effect_closure import (
    _NINTH_EXEC,
    _assert_ninth_not_authorized,
    _helpers_source,
    _scope,
    _unit,
)


def _alias_unit(body: str) -> object:
    return _unit(
        "import helpers\nimport types, operator, copy\n"
        "from operator import methodcaller, attrgetter\n"
        "from functools import partial\n"
        "def evil(state, value):\n"
        "    state.bypass_filter = value\n"
        "def handler(request, bypass_filter=False):\n"
        "    request.state.bypass_filter = True\n"
        + "\n".join(f"    {ln}" for ln in body.split("\n"))
        + "\n    return request.state.bypass_filter"
    )


def _interproc_unit(call: str) -> object:
    nested = """
def install(fn):
    global write_state
    write_state = fn
def write_state(state, value):
    state.bypass_filter = True
""".strip()
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
    return analyze_bypass_authority_unit(
        files,
        entry_path="app/routes.py",
        function_name="handler",
        bypass_fields=frozenset({"bypass_filter"}),
        scope_proof=_scope(*files, import_roots=("app",)),
    )


def _cf_body(head: str, adapter: str) -> tuple[str, str]:
    ex = _NINTH_EXEC
    fn = "list.append"
    vals = '[partial(setattr, ns, "e")]'
    imp = (
        "import types\nfrom functools import partial\n"
        "import operator\nimport builtins\nimport copy\n"
    )
    seed = {
        "setdefault_get": (
            "d={}\nfor k in vb:\n    d.setdefault(k, vb.get(k))"
        ),
        "setitem_get": (
            "d={}\nfor k in vb:\n    operator.setitem(d, k, vb.get(k))"
        ),
        "ior_get": (
            "d={}\nfor k in vb:\n    d.__ior__({k: vb.get(k)})"
        ),
        "dictcomp_list_vb": "d={k: vb.get(k) for k in list(vb)}",
        "partial_setitem": (
            "d={}\nfor k in vb:\n"
            "    partial(operator.setitem, d)(k, vb.get(k))"
        ),
        "bitor_dictcomp": "d={} | {k: vb.get(k) for k in vb}",
        "ior_dict_vb": "d={}\noperator.ior(d, dict(vb))",
        "update_copy": (
            "d={}\nfor k in vb:\n    d.update(copy.copy({k: vb.get(k)}))"
        ),
    }[head]
    # CF adapters only apply to Name-bind / bare; BoolOp wrapping a
    # multi-line for-seed is not a valid composition.
    if adapter == "name_bind" and head == "dictcomp_list_vb":
        body = (
            f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
            f"raw={{k: vb.get(k) for k in list(vb)}}; d=raw\n"
            f'pm=partial(d["map"], {fn})\n'
            f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})"
        )
    elif adapter == "bool_or" and head in {
        "dictcomp_list_vb",
        "bitor_dictcomp",
    }:
        body = (
            f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
            f"d=(0 or {{k: vb.get(k) for k in list(vb)}})\n"
            f'pm=partial(d["map"], {fn})\n'
            f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})"
        )
    else:
        body = (
            f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
            f"{seed}\n"
            f'pm=partial(d["map"], {fn})\n'
            f"list(pm([xs:=[]], {vals})); xs[0](exec)\nns.e({ex})"
        )
    return body, imp


def _identity_body(head: str, adapter: str) -> tuple[str, str]:
    imp = (
        "import operator\nimport builtins\nfrom functools import partial\n"
        "from itertools import filterfalse\n"
    )
    cores = {
        "star_zip_getitem": (
            "operator.getitem([*zip([list.__dict__['sort']])],0)[0]"
        ),
        "star_enumerate": "[*enumerate(zip([list.__dict__['sort']]))][0][1][0]",
        "filter_zip": "list(filter(None, zip([list.__dict__['sort']])))[0][0]",
        "map_zip": "list(map(lambda t: t, zip([list.__dict__['sort']])))[0][0]",
        "partial_getitem_zip": (
            "partial(operator.getitem,[*zip([list.__dict__['sort']])],0)()[0]"
        ),
        "filterfalse_zip": (
            "list(filterfalse(lambda x: False, "
            "zip([list.__dict__['sort']])))[0][0]"
        ),
        "filter_bool_zip": (
            "list(filter(bool, zip([list.__dict__['sort']])))[0][0]"
        ),
    }
    core = cores[head]
    if adapter == "name_bind" and head == "star_zip_getitem":
        body = (
            "xs=[*zip([list.__dict__['sort']])]\n"
            "g=operator.getitem(xs,0)[0].__get__(None, list)\n"
            "ys=[Mut]\ng(ys, key=type.__call__)"
        )
    elif adapter == "list0" and head == "star_zip_getitem":
        body = (
            "g=[operator.getitem([*zip([list.__dict__['sort']])],0)[0]][0]"
            ".__get__(None, list)\nxs=[Mut]\ng(xs, key=type.__call__)"
        )
    elif adapter == "bool_or" and head == "star_zip_getitem":
        body = (
            "g=(0 or operator.getitem)([*zip([list.__dict__['sort']])],0)[0]"
            ".__get__(None, list)\nxs=[Mut]\ng(xs, key=type.__call__)"
        )
    else:
        peeled = wrap_adapter(adapter, core) if adapter != "bare" else core
        body = (
            f"g={peeled}.__get__(None, list)\n"
            f"xs=[Mut]\ng(xs, key=type.__call__)"
        )
    return body, imp


def _lexical_body(head: str, adapter: str) -> tuple[str, str]:
    imp = (
        "import operator\nfrom functools import partial\n"
        "import copy\nimport builtins"
    )
    arms = {
        "itruediv": "operator.itruediv(2,1)",
        "dunder_itruediv": "operator.__itruediv__(2,1)",
        "getattr_itruediv": 'getattr(operator,"itruediv")(2,1)',
        "packed_itruediv": "[operator.itruediv][0](2,1)",
        "iadd": "operator.iadd([1],[1])",
        "dunder_ifloordiv": "operator.__ifloordiv__(2,1)",
        "index": "operator.index(1)",
    }
    arm = arms[head]
    if adapter == "bool_or" and head == "itruediv":
        arm = "(0 or operator.itruediv)(2,1)"
    elif adapter == "list0" and head == "itruediv":
        arm = "[operator.itruediv][0](2,1)"
    elif adapter == "bool_or" and head == "iadd":
        arm = "(0 or operator.iadd)([1],[1])"
    elif adapter == "list0" and head == "iadd":
        arm = "[operator.iadd][0]([1],[1])"
    body = (
        f"d={{Mut:1}}\nnew=partial.__new__\n"
        f"e=({arm} and new)(partial, copy.copy, d)()\n"
        f"e|={{}}\nC,=e.keys()\nC()"
    )
    return body, imp


def _alias_body(head: str, adapter: str) -> str:
    prefix = (
        'ns=types.__dict__\nkeys={"x":"MappingProxyType"}\n'
        "from functools import partial\n"
        "from types import MappingProxyType\n"
        "from collections import OrderedDict\n"
        'g=getattr([partial(copy.copy)],"pop")\n'
        "oc=operator.call\n"
    )
    setup = ""
    mid = {
        "dict_ctor_pack": 'dict({"gi":operator.getitem})["gi"]',
        "name_dict_pack": 'd["gi"]',
        "mpt_pack": 'MappingProxyType({"gi":operator.getitem})["gi"]',
        "attrgetter_call": "ag(operator.getitem)",
        "next_iter_dict": 'next(iter([{"gi":operator.getitem}]))["gi"]',
        "od_ctor": 'OrderedDict({"gi":operator.getitem})["gi"]',
    }[head]
    if head == "name_dict_pack":
        setup = 'd={"gi":operator.getitem}\n'
    elif head == "attrgetter_call":
        setup = 'ag=attrgetter("__call__")\n'
    if adapter == "bool_or" and head == "dict_ctor_pack":
        mid = '(0 or dict({"gi":operator.getitem}))["gi"]'
    elif adapter == "list0" and head == "dict_ctor_pack":
        mid = '[dict({"gi":operator.getitem})["gi"]][0]'
    elif adapter == "list0" and head == "attrgetter_call":
        mid = "[ag(operator.getitem)][0]"
    elif adapter == "bool_or" and head == "attrgetter_call":
        mid = "(0 or ag)(operator.getitem)"
    elif adapter == "list0" and head == "name_dict_pack":
        mid = '[d["gi"]][0]'
    elif adapter == "bool_or" and head == "name_dict_pack":
        mid = '(0 or d)["gi"]'
    return (
        prefix
        + setup
        + f"c=oc({mid},[g.__call__],0)(*[0])(keys)\n"
        + 'c["z"]=c.pop("x"); k=c.get("z")\n'
        + 'Proxy=getattr(ns,"get")(k)\ns=Proxy({"s":request.state})["s"]\n'
        + "s.bypass_filter=bypass_filter"
    )


def _class_body(head: str, adapter: str) -> tuple[str, str]:
    ex = _NINTH_EXEC
    imp = (
        "import types\nimport operator\nimport copy\n"
        "from functools import partial\nfrom collections import ChainMap\n"
        "from operator import iconcat, methodcaller, attrgetter"
    )
    grows = {
        "iconcat_list_copy_maps": 'iconcat(xs, list.copy(cm.maps))',
        "iadd_list_copy_parents": (
            'operator.iadd(xs, list.copy(cm.parents.maps))'
        ),
        "extend_list_copy_maps": "xs.extend(list.copy(cm.maps))",
        "methodcaller_iadd_copy": (
            'methodcaller("__iadd__", list.copy(cm.maps))(xs)'
        ),
        "attrgetter_maps": (
            'iconcat(xs, list.copy(attrgetter("maps")(cm)))'
        ),
        "getattr_maps": 'iconcat(xs, list.copy(getattr(cm,"maps")))',
    }
    grow = grows[head]
    if adapter == "bool_or" and head == "iconcat_list_copy_maps":
        grow = "(0 or iconcat)(xs, list.copy(cm.maps))"
    elif adapter == "list0" and head == "iconcat_list_copy_maps":
        grow = "[iconcat][0](xs, list.copy(cm.maps))"
    elif adapter == "bool_or" and head == "attrgetter_maps":
        grow = 'iconcat(xs, list.copy((0 or attrgetter("maps"))(cm)))'
    elif adapter == "list0" and head == "attrgetter_maps":
        grow = 'iconcat(xs, list.copy([attrgetter("maps")][0](cm)))'
    idx = "1" if "parents" in head else "2"
    body = (
        f"ns=types.SimpleNamespace()\n"
        f"cm=ChainMap({{}}, vars(ns)); xs=[{{}}]; "
        f"{grow}; xs[{idx}][\"e\"]=exec\nns.e({ex})"
    )
    return body, imp


def _interproc_call(head: str, adapter: str) -> str:
    cores = {
        "unbound_decoder_decode": (
            "import json\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*json.JSONDecoder.decode(json.JSONDecoder(),'[]')); f(evil)"
        ),
        "from_import_literal_eval": (
            "from ast import literal_eval as le\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*le('[]')); f(evil)"
        ),
        "getattr_iadd_empty": (
            "from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "xs=[]; f=e(*getattr(xs,'__iadd__')(())); f(evil)"
        ),
        "getattr_from_iterable": (
            "import itertools as it\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*getattr(it.chain,'from_iterable')(())); f(evil)"
        ),
        "raw_decode_bound": (
            "import json\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*json.JSONDecoder().raw_decode('[]')[0]); f(evil)"
        ),
        "pickle_loads": (
            "import pickle\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*pickle.loads(pickle.dumps([]))); f(evil)"
        ),
        "getattr_tuple_getitem_slice0": (
            "from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "f=e(*getattr((),'__getitem__')(slice(0))); f(evil)"
        ),
    }
    call = cores[head]
    if adapter == "name_bind" and head == "unbound_decoder_decode":
        call = (
            "import json\n"
            "    from contextlib import nullcontext; args=(n.install,)\n"
            "    cm=nullcontext(*args); e=cm.__enter__; "
            "dec=json.JSONDecoder.decode; "
            "f=e(*dec(json.JSONDecoder(),'[]')); f(evil)"
        )
    return call


# Fast-core matrix rows: adapter × family head (keep unit CI lean).
_MATRIX_CASES: list[tuple[str, str, str]] = []
_CF_FOR_SEEDS = frozenset(
    {
        "setdefault_get",
        "setitem_get",
        "ior_get",
        "partial_setitem",
        "update_copy",
    }
)
for family, heads in FAMILY_HEADS.items():
    for head in heads:
        for adapter in ("bare", "list0", "bool_or", "name_bind"):
            if adapter == "list0" and family in {"cf", "interproc"}:
                continue
            if adapter == "name_bind" and family == "lexical":
                continue
            if adapter == "bool_or" and family == "interproc":
                continue
            # BoolOp around multi-line CF for-seeds is not a valid composition.
            if adapter == "bool_or" and family == "cf" and head in _CF_FOR_SEEDS:
                continue
            _MATRIX_CASES.append((family, head, adapter))


@pytest.mark.parametrize(
    ("family", "head", "adapter"),
    _MATRIX_CASES,
    ids=[f"{f}/{h}/{a}" for f, h, a in _MATRIX_CASES],
)
def test_pe_peel_matrix_never_authorized(
    family: str, head: str, adapter: str
) -> None:
    """Poison / Mut reachable through adapter×head ⇒ never authorize."""

    if family == "cf":
        body, imp = _cf_body(head, adapter)
        if adapter in {"list0", "bool_or", "getattr_fn", "partial_idle"}:
            # CF seed adapters that break Assign shape stay on bare heads.
            if "for k" not in body and head != "dictcomp_list_vb":
                pytest.skip("adapter incompatible with CF for-loop seed")
        _assert_ninth_not_authorized(((body, imp),))
        return
    if family == "identity":
        body, imp = _identity_body(head, adapter)
        _assert_ninth_not_authorized(((body, imp),))
        return
    if family == "lexical":
        body, imp = _lexical_body(head, adapter)
        _assert_ninth_not_authorized(((body, imp),))
        return
    if family == "alias":
        findings = _alias_unit(_alias_body(head, adapter))
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"
        return
    if family == "class":
        body, imp = _class_body(head, adapter)
        _assert_ninth_not_authorized(((body, imp),))
        return
    if family == "interproc":
        findings = _interproc_unit(_interproc_call(head, adapter))
        assert findings[0].status != "authorized"
        assert findings[0].reason != "source_proved_server_authority_write"
        return
    raise AssertionError(f"unknown family {family}")


@pytest.mark.parametrize(
    "body",
    (
        "import types\nfrom functools import partial\nimport builtins\n"
        "ns=types.SimpleNamespace()\n"
        'd=vars(builtins); pm=partial(d["map"], list.append)\n'
        "list(pm([xs:=[]], [partial(setattr, ns, 'x')])); xs[0](1)\nns.x",
        "import types\nfrom collections import ChainMap\n"
        "from operator import iconcat\n"
        "ns=types.SimpleNamespace()\n"
        "cm=ChainMap({}, vars(ns)); xs=[{}]; "
        "iconcat(xs, list.copy(cm.maps))\nlen(xs)",
        "operator.itruediv(2,1) and len([1])",
        "import json\njson.JSONDecoder().decode('[1]')",
        "(0 or operator.itruediv)(2,1) and len([1])",
        "[operator.itruediv][0](2,1) and len([1])",
    ),
)
def test_pe_peel_matrix_positive_inert_authorized(body: str) -> None:
    """Same adapters with inert callees must remain authorized."""

    src = (
        "import helpers\nimport copy\nimport types\nimport operator\n"
        "def handler(request, bypass_filter=False):\n"
        "    request.state.bypass_filter = True\n"
        + "\n".join(f"    {ln}" for ln in body.split("\n"))
        + "\n    return request.state.bypass_filter"
    )
    findings = _unit(src)
    assert findings[0].status == "authorized", body
    assert findings[0].reason == "source_proved_server_authority_write", body


def test_pe_peel_algebra_version_at_least_1_3_0() -> None:
    """Algebra tip bumps persistent cache version."""

    parts = tuple(
        int(p) for p in PERSISTENT_FASTAPI_STATE_IMPLEMENTATION_VERSION.split(".")
    )
    assert parts >= (1, 3, 0)


def test_fast_core_adapters_catalog_nonempty() -> None:
    assert len(FAST_CORE_ADAPTERS) >= 8
    assert len(_MATRIX_CASES) >= 40
