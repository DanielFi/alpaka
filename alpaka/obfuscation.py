import re

import lief.DEX as DEX


OBFUSCATED_CLASS_NAME_PATTERN = re.compile(r'([^/]+/){,1}[^/]+|.+[/$][^/$]{,3}')
OBFUSCATED_INNER_NAME_PATTERN = re.compile(r'\w[\w\d]{,2}')

def is_obfuscated_class_name(fullname: str) -> bool:
    return OBFUSCATED_CLASS_NAME_PATTERN.fullmatch(fullname) is not None

def is_obfuscated_class(cls: DEX.Class) -> bool:
    return is_obfuscated_class_name(cls.fullname)

def is_obfuscated_field(field: DEX.Field) -> bool:
    return OBFUSCATED_INNER_NAME_PATTERN.match(field.name) is not None

def is_obfuscated_method(method: DEX.Method) -> bool:
    return DEX.ACCESS_FLAGS.CONSTRUCTOR not in method.access_flags and OBFUSCATED_INNER_NAME_PATTERN.match(method.name) is not None
