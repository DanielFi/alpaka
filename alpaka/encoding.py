from collections.abc import Hashable

from lief import DEX
from lief.DEX import ACCESS_FLAGS

from .obfuscation import is_obfuscated_class, is_obfuscated_class_name, is_obfuscated_field, is_obfuscated_method
from .utils import is_primitive_type


def encode_access_flags(access_flags: list[ACCESS_FLAGS]) -> int:
    return sum(int(flag.value) for flag in access_flags)


def encode_simple_class(fullname: str) -> str | tuple[()]:
    if not is_obfuscated_class_name(fullname):
        return fullname

    return ()


def encode_type(typ: DEX.Type) -> tuple[int, int | str | tuple[()]]:
    utyp = typ.underlying_array_type if typ.type == DEX.Type.TYPES.ARRAY else typ
    return (
        # array dimensionality (0 for non-arrays)
        typ.dim,
        # actual type: enum for primitives, simple class encoding for classes
        int(utyp.value.value) if is_primitive_type(utyp) else encode_simple_class(str(utyp)),
    )


def encode_field(field: DEX.Field) -> Hashable:
    # Workaround lief typing bug
    assert field.type is not None

    return (
        # name if non-obfuscated, otherwise None
        None if is_obfuscated_field(field) else field.name,
        # access flags
        encode_access_flags(field.access_flags),
        # type
        encode_type(field.type),
    )


def encode_method(method: DEX.Method) -> Hashable:
    # Workaround lief typing bug
    assert method.prototype is not None and method.prototype.return_type is not None

    return (
        # name if non-obfuscated, otherwise None
        None if is_obfuscated_method(method) else method.name,
        # access flags
        encode_access_flags(method.access_flags),
        # return type
        encode_type(method.prototype.return_type),
        # parameter types
        tuple(encode_type(parameter) for parameter in method.prototype.parameters_type),
        # byte code length
        # divided by a small constant B=2 to create small buckets, since it might change
        # naturally across compilations
        # B - 1 must be added before division to ensure that only empty methods are in
        # the first bucket
        (len(method.bytecode) + (2 - 1)) // 2,
    )


def encode_class(cls: DEX.Class) -> Hashable:
    if not is_obfuscated_class(cls):
        return cls.fullname

    # Workaround lief typing bug
    assert cls.parent is not None

    return (
        # access flags
        encode_access_flags(cls.access_flags),
        # parent class
        None if not cls.has_parent else (encode_simple_class(cls.parent.fullname)),
        # fields
        tuple(encode_field(field) for field in cls.fields),
        # methods
        tuple(encode_method(method) for method in cls.methods),
    )
