"""Bounded generative peel property: Mut/evil reachable ⇒ never authorize.

Seeded RNG builds peel nests from the catalog up to a small budget. Failures
replay with seed + program string printed in the assertion message.
"""

from __future__ import annotations

import random

import pytest

from tests.pe_peel_catalog import FAST_CORE_ADAPTERS, wrap_adapter
from tests.test_executed_expression_effect_closure import (
    _NINTH_EXEC,
    _ninth_src,
    _unit,
)

# Fixed CI seeds — keep unit runtime bounded (50–100 programs).
_PROPERTY_SEEDS: tuple[int, ...] = (
    17340,
    17341,
    17342,
    17343,
    17344,
    40173,
    90173,
    12026,
)

_IDENTITY_CORES: tuple[str, ...] = (
    "operator.getitem([*zip([list.__dict__['sort']])],0)[0]",
    "list(filter(None, zip([list.__dict__['sort']])))[0][0]",
    "list(map(lambda t: t, zip([list.__dict__['sort']])))[0][0]",
    "[*enumerate(zip([list.__dict__['sort']]))][0][1][0]",
)

_LEXICAL_ARMS: tuple[str, ...] = (
    "operator.itruediv(2,1)",
    "operator.__itruediv__(2,1)",
    'getattr(operator,"itruediv")(2,1)',
    "[operator.itruediv][0](2,1)",
    "(0 or operator.itruediv)(2,1)",
)

_CF_SEEDS: tuple[str, ...] = (
    "d={}\nfor k in vb:\n    d.setdefault(k, vb.get(k))",
    "d={}\nfor k in vb:\n    operator.setitem(d, k, vb.get(k))",
    "d={k: vb.get(k) for k in list(vb)}",
    "d=dict({k: vb.get(k) for k in vb})",
)

_CLASS_GROWS: tuple[str, ...] = (
    "iconcat(xs, list.copy(cm.maps))",
    "operator.iadd(xs, list.copy(cm.maps))",
    "xs.extend(list.copy(cm.maps))",
    '(0 or iconcat)(xs, list.copy(cm.maps))',
    "[iconcat][0](xs, list.copy(cm.maps))",
)


def _gen_identity(rng: random.Random) -> tuple[str, str]:
    core = rng.choice(_IDENTITY_CORES)
    adapter = rng.choice(("bare", "list0", "bool_or"))
    if adapter == "list0":
        core = f"[{core}][0]"
    elif adapter == "bool_or" and core.startswith("operator.getitem"):
        core = core.replace("operator.getitem", "(0 or operator.getitem)", 1)
    body = (
        f"g={core}.__get__(None, list)\n"
        f"xs=[Mut]\ng(xs, key=type.__call__)"
    )
    imp = "import operator\nimport builtins\nfrom functools import partial\n"
    return body, imp


def _gen_lexical(rng: random.Random) -> tuple[str, str]:
    arm = rng.choice(_LEXICAL_ARMS)
    body = (
        f"d={{Mut:1}}\nnew=partial.__new__\n"
        f"e=({arm} and new)(partial, copy.copy, d)()\n"
        f"e|={{}}\nC,=e.keys()\nC()"
    )
    imp = (
        "import operator\nfrom functools import partial\n"
        "import copy\nimport builtins"
    )
    return body, imp


def _gen_cf(rng: random.Random) -> tuple[str, str]:
    ex = _NINTH_EXEC
    seed = rng.choice(_CF_SEEDS)
    body = (
        f"ns=types.SimpleNamespace()\nvb=vars(builtins)\n"
        f"{seed}\n"
        f'pm=partial(d["map"], list.append)\n'
        f'list(pm([xs:=[]], [partial(setattr, ns, "e")])); xs[0](exec)\n'
        f"ns.e({ex})"
    )
    imp = (
        "import types\nfrom functools import partial\n"
        "import operator\nimport builtins\n"
    )
    return body, imp


def _gen_class(rng: random.Random) -> tuple[str, str]:
    ex = _NINTH_EXEC
    grow = rng.choice(_CLASS_GROWS)
    body = (
        f"ns=types.SimpleNamespace()\n"
        f"cm=ChainMap({{}}, vars(ns)); xs=[{{}}]; "
        f'{grow}; xs[2]["e"]=exec\nns.e({ex})'
    )
    imp = (
        "import types\nimport operator\nimport copy\n"
        "from functools import partial\nfrom collections import ChainMap\n"
        "from operator import iconcat, methodcaller"
    )
    return body, imp


_GENERATORS = (_gen_identity, _gen_lexical, _gen_cf, _gen_class)


def _programs_for_seed(seed: int, *, n: int = 8) -> list[tuple[str, str, str]]:
    rng = random.Random(seed)
    out: list[tuple[str, str, str]] = []
    for i in range(n):
        gen = rng.choice(_GENERATORS)
        body, imp = gen(rng)
        out.append((f"seed={seed}/i={i}/{gen.__name__}", body, imp))
    return out


@pytest.mark.parametrize("seed", _PROPERTY_SEEDS)
def test_pe_peel_property_mut_reachable_never_authorized(seed: int) -> None:
    """Seeded nests: if Mut/evil is reachable, analyzer must not authorize."""

    leaked: list[str] = []
    for label, body, imp in _programs_for_seed(seed):
        findings = _unit(_ninth_src(body, imports=imp))
        if (
            findings[0].status == "authorized"
            or findings[0].reason == "source_proved_server_authority_write"
        ):
            leaked.append(f"{label}\n{body}")
    assert not leaked, (
        "property false PASS (replay with seed):\n"
        + "\n==========\n".join(leaked)
    )


def test_pe_peel_property_batch_covers_budget() -> None:
    """Unit CI generates a bounded batch (replayable via seeds)."""

    total = sum(len(_programs_for_seed(s)) for s in _PROPERTY_SEEDS)
    assert 50 <= total <= 100


def test_pe_peel_property_positive_inert_still_authorized() -> None:
    """Inert counterparts of generative shapes remain authorized."""

    for body in (
        "operator.itruediv(2,1) and len([1])",
        "(0 or operator.itruediv)(2,1) and len([1])",
        "import types\nfrom collections import ChainMap\n"
        "from operator import iconcat\n"
        "ns=types.SimpleNamespace()\n"
        "cm=ChainMap({}, vars(ns)); xs=[{}]; "
        "iconcat(xs, list.copy(cm.maps))\nlen(xs)",
    ):
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


def test_wrap_adapter_composes() -> None:
    assert wrap_adapter("list0", "x") == "[x][0]"
    assert wrap_adapter("bool_or", "x") == "(0 or x)"
    assert "list0" in FAST_CORE_ADAPTERS
