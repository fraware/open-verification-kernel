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
        # Forty-first-pass atoms (shared peels).
        "partial_setitem",
        "bitor_dictcomp",
        "ior_dict_vb",
        "update_copy",
        # Forty-second-pass atoms (shared peels).
        "name_setitem_dunder",
        "augassign_ior_copy_dictcomp",
        "chainmap_getattr_setdefault",
    ),
    "identity": (
        "star_zip_getitem",
        "star_enumerate",
        "filter_zip",
        "map_zip",
        "partial_getitem_zip",
        "filterfalse_zip",
        "filter_bool_zip",
        # Forty-second-pass atoms (shared peels).
        "from_iterable_zip",
        "name_zip_star",
        "cycle_zip",
        "filter_true_zip",
    ),
    "lexical": (
        "itruediv",
        "dunder_itruediv",
        "getattr_itruediv",
        "packed_itruediv",
        "iadd",
        "dunder_ifloordiv",
        "index",
    ),
    "alias": (
        "dict_ctor_pack",
        "name_dict_pack",
        "mpt_pack",
        "attrgetter_call",
        "next_iter_dict",
        "od_ctor",
        # Leftover atoms closed at 1.6.0 (shared peels).
        "name_copy_get",
        "operator_getitem_pack",
        "partial_getattr_callcall",
        # Forty-second-pass atoms (shared peels).
        "list0_copy_gi",
        "next_values_gi",
        "fromkeys_gi",
        "ig_call_applied",
    ),
    "class": (
        "iconcat_list_copy_maps",
        "iadd_list_copy_parents",
        "extend_list_copy_maps",
        "methodcaller_iadd_copy",
        "attrgetter_maps",
        "getattr_maps",
        "append_list_copy_maps",
        # Forty-second-pass atoms (shared peels).
        "binop_add_list_maps",
        "append_list_maps",
        "append_maps_slice",
    ),
    "interproc": (
        "unbound_decoder_decode",
        "from_import_literal_eval",
        "getattr_iadd_empty",
        "getattr_from_iterable",
        "raw_decode_bound",
        "pickle_loads",
        "getattr_tuple_getitem_slice0",
        "packed_from_iterable",
        "csv_reader_empty",
        "name_getattr_slice0",
        # Forty-second-pass atoms (shared peels).
        "name_getattr_decode",
        "getattr_raw_decode",
        "pickle_load",
        "zlib_decompress",
        "itemgetter_slice0",
        "csv_dict_reader",
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


# Non-material / held-out OOS (do not "close" — TypeError empties / FormalPR).
# These must remain unknown rather than authorized; they are not false-PASS digs.
NON_MATERIAL_OOS: tuple[str, ...] = (
    "binascii.b2a_uu / a2b_uu empty codec packs that raise at runtime",
    "itertools.product() arity / empty-product one-tuple yield",
    "itertools.partition / combinations*(..., 0) non-material empties",
    "next(tee(...)) arity / tee half misuse that TypeErrors",
    "list.extend TypeError empties / FormalPR freeze",
    # Idle ``partial(operator.getitem)(carrier, idx)()`` — empty apply on the
    # zip-pair Tuple TypeErrors (Unknown > false authorize; do not materialize).
    "partial(operator.getitem)([*zip(...)],0)() empty-apply TypeError",
    "FormalPR freeze / #87 held-out until human gate",
)

# Closed at 1.6.0 via shared peels + catalog atoms (was FORTY_FIRST_LEFTOVERS).
FORTY_FIRST_LEFTOVERS: tuple[str, ...] = ()

# Closed at 1.7.0 via shared peels + catalog atoms (was FORTY_SECOND leftovers).
FORTY_SECOND_LEFTOVERS: tuple[str, ...] = ()
