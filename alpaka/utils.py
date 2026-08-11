from __future__ import annotations

from typing import TYPE_CHECKING

from lief import DEX
from typing_extensions import TypeIs

if TYPE_CHECKING:

    class PrimitiveDexType(DEX.Type):
        @property
        def value(self) -> DEX.Type.PRIMITIVES: ...


def is_primitive_type(dex_type: DEX.Type) -> TypeIs[PrimitiveDexType]:
    return dex_type.type == DEX.Type.TYPES.PRIMITIVE
