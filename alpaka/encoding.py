import lief.DEX as DEX

from .obfuscation import is_obfuscated_class_name, is_obfuscated_class, is_obfuscated_field, is_obfuscated_method


def encode_access_flags(access_flags):
    return sum(int(flag.value) for flag in access_flags)

def encode_simple_class(fullname: str):
    if not is_obfuscated_class_name(fullname):
        return fullname

    return tuple()

def encode_type(typ: DEX.Type):
    utyp = typ.underlying_array_type if typ.type == DEX.Type.TYPES.ARRAY else typ
    return (
        # array dimensionality (0 for non-arrays)
        typ.dim,
        # actual type: enum for primitives, simple class encoding for classes
        int(utyp.value.value) if utyp.type == DEX.Type.TYPES.PRIMITIVE else encode_simple_class(str(utyp))
    )

def encode_field(field: DEX.Field):
    return (
        # name if non-obfuscated, otherwise None
        None if is_obfuscated_field(field) else field.name,
        # access flags
        encode_access_flags(field.access_flags),
        # type
        encode_type(field.type)
    )

def encode_method(method: DEX.Method):
    return (
        # name if non-obfuscated, otherwise None
        None if is_obfuscated_method(method) else method.name,
        # access flags
        encode_access_flags(method.access_flags),
        # return type
        encode_type(method.prototype.return_type),
        # parameter types
        tuple(
            encode_type(parameter) for parameter in method.prototype.parameters_type
        )
    )

def encode_class(cls: DEX.Class):
    if not is_obfuscated_class(cls):
        return cls.fullname

    return (
        # access flags
        encode_access_flags(cls.access_flags),
        # parent class
        None if not cls.has_parent else (encode_simple_class(cls.parent.fullname)),
        # fields
        tuple(
            encode_field(field) for field in cls.fields
        ),
        # methods
        tuple(
            encode_method(method) for method in cls.methods
        )
    )
