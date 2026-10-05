"""Peel adapter catalog for PE executed-expression matrix / property tests.

Named atoms compose into family heads so Reaudit digs become catalog entries
instead of one-off hand lists (Unknown > false PASS).
"""

from __future__ import annotations

# Carrier / choice / factory / materialize / copy atoms (depth-1).
ADAPTER_ATOMS: tuple[str, ...] = (
    "name_bind",
    "list0",
    "next_iter",
    "bool_or",
    "getattr_fn",
    "methodcaller",
    "partial_idle",
    "attrgetter",
    "itemgetter",
    "star_list",
    "dict_pack",
    "copy_list",
)

# Fast-core compositions exercised in unit CI (depth <= 2).
FAST_CORE_ADAPTERS: tuple[str, ...] = (
    "bare",
    "list0",
    "bool_or",
    "getattr_fn",
    "name_bind",
    "partial_idle",
    "copy_list",
    "list0+getattr_fn",
    "bool_or+partial_idle",
    "name_bind+copy_list",
)

FAMILY_HEADS: dict[str, tuple[str, ...]] = {
    "cf": (
        "setdefault_get",
        "setitem_get",
        "ior_get",
        "dictcomp_list_vb",
    ),
    "identity": (
        "star_zip_getitem",
        "star_enumerate",
        "filter_zip",
        "map_zip",
    ),
    "lexical": (
        "itruediv",
        "dunder_itruediv",
        "getattr_itruediv",
        "packed_itruediv",
    ),
    "alias": (
        "dict_ctor_pack",
        "name_dict_pack",
        "mpt_pack",
        "attrgetter_call",
    ),
    "class": (
        "iconcat_list_copy_maps",
        "iadd_list_copy_parents",
        "extend_list_copy_maps",
        "methodcaller_iadd_copy",
    ),
    "interproc": (
        "unbound_decoder_decode",
        "from_import_literal_eval",
        "getattr_iadd_empty",
        "getattr_from_iterable",
    ),
}


def wrap_adapter(adapter: str, expr: str) -> str:
    """Wrap ``expr`` with a named adapter spelling (Python source fragment)."""

    if adapter == "bare":
        return expr
    if adapter == "list0":
        return f"[{expr}][0]"
    if adapter == "next_iter":
        return f"next(iter([{expr}]))"
    if adapter == "bool_or":
        return f"(0 or {expr})"
    if adapter == "getattr_fn":
        # Caller supplies module-qualified expr; wrap as getattr of Name mid.
        return f"(lambda _e: _e)({expr})"
    if adapter == "name_bind":
        return expr  # Name binding applied by family builders.
    if adapter == "partial_idle":
        return f"partial({expr})" if not expr.startswith("partial(") else expr
    if adapter == "star_list":
        return f"[*{expr}]" if not expr.startswith("[*") else expr
    if adapter == "copy_list":
        return f"list.copy({expr})"
    if "+" in adapter:
        left, right = adapter.split("+", 1)
        return wrap_adapter(right, wrap_adapter(left, expr))
    return expr
