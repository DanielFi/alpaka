import logging
from collections import Counter
from collections.abc import Callable, Generator, Hashable
from typing import TypeVar

from lief import DEX

from .encoding import encode_class, encode_field, encode_method
from .enigma import EnigmaClass, EnigmaField, EnigmaMapping, EnigmaMethod
from .extraction import get_classes_from_dexs
from .heckel_diff import diff as heckel_diff
from .obfuscation import is_obfuscated_class_name
from .utils import is_primitive_type

logger = logging.getLogger(__name__)


def _get_vote_for_types(
    classes_a: dict[str, DEX.Class], classes_b: dict[str, DEX.Class], type_a: DEX.Type, type_b: DEX.Type
) -> tuple[DEX.Class, DEX.Class] | None:
    type_a = type_a.underlying_array_type
    type_b = type_b.underlying_array_type

    if type_a.type != DEX.Type.TYPES.CLASS or type_b.type != DEX.Type.TYPES.CLASS:
        return None

    class_a = classes_a.get(str(type_a))
    class_b = classes_b.get(str(type_b))

    if class_a is not None and class_b is not None:
        return class_a, class_b

    return None


def _gather_votes(
    classes_a: dict[str, DEX.Class], classes_b: dict[str, DEX.Class], class_a: DEX.Class, class_b: DEX.Class
) -> Generator[tuple[DEX.Class, DEX.Class], None, None]:
    for field_a, field_b in zip(class_a.fields, class_b.fields, strict=False):
        # Workaround lief typing bug
        assert field_a.type is not None and field_b.type is not None

        vote = _get_vote_for_types(classes_a, classes_b, field_a.type, field_b.type)
        if vote is not None:
            yield vote

    for method_a, method_b in zip(class_a.methods, class_b.methods, strict=False):
        # Workaround lief typing bug
        assert method_a.prototype is not None and method_b.prototype is not None
        assert method_a.prototype.return_type is not None and method_b.prototype.return_type is not None

        vote = _get_vote_for_types(classes_a, classes_b, method_a.prototype.return_type, method_b.prototype.return_type)
        if vote is not None:
            yield vote

        for param_a, param_b in zip(
            method_a.prototype.parameters_type, method_b.prototype.parameters_type, strict=False
        ):
            vote = _get_vote_for_types(classes_a, classes_b, param_a, param_b)
            if vote is not None:
                yield vote


def match_classes(
    dexs_a: list[DEX.File], dexs_b: list[DEX.File], only_obfuscated: bool = False, propagate: bool = True
) -> dict[DEX.Class, DEX.Class]:
    classes_a = get_classes_from_dexs(dexs_a)
    classes_b = get_classes_from_dexs(dexs_b)

    logger.info(f"classes in input A: {len(classes_a)}")
    logger.info(f"classes in input B: {len(classes_b)}")

    mapping = _match_items(classes_a, classes_b, encode_class, sentinals=False)

    logger.info(f"heckel diff mapped classes: {len(mapping)}")

    classes_map_a = {cls.fullname: cls for cls in classes_a}
    classes_map_b = {cls.fullname: cls for cls in classes_b}

    if propagate:
        votes = Counter(
            vote
            for class_a, class_b in mapping.items()
            for vote in _gather_votes(classes_map_a, classes_map_b, class_a, class_b)
        )

        logger.info(f"propagation votes: {len(votes)} ({votes.total()} total)")

        mapped_a = set(mapping.keys())
        mapped_b = set(mapping.values())

        for class_a, class_b in sorted(votes, key=votes.__getitem__):
            if class_a in mapped_a or class_b in mapped_b:
                continue

            mapping[class_a] = class_b
            mapped_a.add(class_a)
            mapped_b.add(class_b)

        logger.info(f"propagation mapped classes: {len(mapping)}")

    if only_obfuscated:
        mapping = {k: v for k, v in mapping.items() if is_obfuscated_class_name(k.fullname)}

    return mapping


def _lief_type_to_enigma(dex_type: DEX.Type) -> str:
    if dex_type.type == DEX.Type.TYPES.CLASS:
        return str(dex_type)
    if is_primitive_type(dex_type):
        return {
            DEX.Type.PRIMITIVES.BOOLEAN: "Z",
            DEX.Type.PRIMITIVES.BYTE: "B",
            DEX.Type.PRIMITIVES.CHAR: "C",
            DEX.Type.PRIMITIVES.DOUBLE: "D",
            DEX.Type.PRIMITIVES.FLOAT: "F",
            DEX.Type.PRIMITIVES.INT: "I",
            DEX.Type.PRIMITIVES.LONG: "J",
            DEX.Type.PRIMITIVES.SHORT: "S",
            DEX.Type.PRIMITIVES.VOID_T: "V",
        }[dex_type.value]
    return "[" * dex_type.dim + _lief_type_to_enigma(dex_type.underlying_array_type)


def _lief_prototype_to_enigma(prototype: DEX.Prototype) -> str:
    # Workaround lief typing bug
    assert prototype.return_type is not None

    parameters = "".join([_lief_type_to_enigma(p) for p in prototype.parameters_type])
    return_type = _lief_type_to_enigma(prototype.return_type)
    return f"({parameters}){return_type}"


def deobfuscate(
    classes_a: list[DEX.Class],
    classes_b: list[DEX.Class],
    mapping: dict[str, str],
    deobfuscation_mapping: EnigmaMapping,
) -> EnigmaMapping:
    enigma_classes: list[EnigmaClass] = []
    for old_enigma_class in deobfuscation_mapping:
        old_name = f"L{old_enigma_class.name};"
        try:
            new_name = mapping[old_name]
        except KeyError:
            logger.warning(f"failed to map class {old_enigma_class.display_name or '?'} ({old_enigma_class.name})")
            continue

        original_enigma_fields = old_enigma_class.fields.copy()
        original_enigma_methods = set(old_enigma_class.methods)
        new_enigma_class = EnigmaClass(new_name[1:-1], old_enigma_class.display_name)
        enigma_classes.append(new_enigma_class)

        class_a = next(cls for cls in classes_a if cls.fullname == old_name)
        class_b = next(cls for cls in classes_b if cls.fullname == new_name)

        fields = list(zip(class_a.fields, class_b.fields, strict=False))
        for enigma_field in original_enigma_fields:
            try:
                _field_a, field_b = next((f_a, f_b) for f_a, f_b in fields if f_a.name == enigma_field.name)
            except IndexError:
                logger.warning(
                    f"failed to map field {enigma_field.display_name} in "
                    + f"class {new_enigma_class.display_name or '?'} ({new_enigma_class.name})"
                )
                continue

            # Workaround lief typing bug
            assert field_b.type is not None
            new_enigma_class.fields.append(
                EnigmaField(field_b.name, enigma_field.display_name, _lief_type_to_enigma(field_b.type))
            )

        for method_a, method_b in zip(class_a.methods, class_b.methods, strict=False):
            # Workaround lief typing bug
            assert method_a.prototype is not None and method_b.prototype is not None
            for enigma_method in original_enigma_methods:
                if (enigma_method.name == method_a.name) and (
                    enigma_method.prototype == _lief_prototype_to_enigma(method_a.prototype)
                ):
                    break
            else:
                continue

            original_enigma_methods.remove(enigma_method)

            new_enigma_class.methods.append(
                EnigmaMethod(method_b.name, enigma_method.display_name, _lief_prototype_to_enigma(method_b.prototype))
            )

        for enigma_method in original_enigma_methods:
            logger.warning(
                f"failed to map method {enigma_method.display_name} in "
                + f"class {new_enigma_class.display_name or '?'} ({new_enigma_class.name})"
            )

    return EnigmaMapping(enigma_classes)


def match_class_fields(class_a: DEX.Class, class_b: DEX.Class) -> dict[DEX.Field, DEX.Field]:
    fields_a = list(class_a.fields)
    fields_b = list(class_b.fields)

    return _match_items(fields_a, fields_b, encode_field)


def match_class_methods(class_a: DEX.Class, class_b: DEX.Class) -> dict[DEX.Method, DEX.Method]:
    methods_a = list(class_a.methods)
    methods_b = list(class_b.methods)

    return _match_items(methods_a, methods_b, encode_method)


T = TypeVar("T")


def _match_items(
    items_a: list[T], items_b: list[T], encoder: Callable[[T], Hashable], sentinals: bool = True
) -> dict[T, T]:
    # surround the encodings with unique sentinal values to ensure mapping
    # happens even when there are no unique values
    encodings_a: list[Hashable]
    encodings_b: list[Hashable]
    if sentinals:
        encodings_a = ["START"]
        encodings_b = ["START"]
    else:
        encodings_a = []
        encodings_b = []

    encodings_a.extend([encoder(item) for item in items_a])
    encodings_b.extend([encoder(item) for item in items_b])

    if sentinals:
        encodings_a.append("END")
        encodings_b.append("END")

    line_mapping, _reverse_mapping = heckel_diff(encodings_a, encodings_b)
    if sentinals:
        mapping = {
            items_a[k - 1]: items_b[v - 1] for k, v in line_mapping.items() if k != 0 and k != len(encodings_a) - 1
        }
    else:
        mapping = {items_a[k]: items_b[v] for k, v in line_mapping.items()}

    return mapping
