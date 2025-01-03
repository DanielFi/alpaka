from collections import Counter
import logging
from typing import Dict, List

import lief.DEX as DEX

from .encoding import encode_class
from .enigma import EnigmaMapping, EnigmaClass, EnigmaField, EnigmaMethod
from .obfuscation import is_obfuscated_class_name

from .heckel_diff import diff as heckel_diff


logger = logging.getLogger(__name__)

def _get_vote_for_types(type_a, type_b):
    type_a = type_a.underlying_array_type
    type_b = type_b.underlying_array_type

    if type_a.type != DEX.Type.TYPES.CLASS or type_b.type != DEX.Type.TYPES.CLASS:
        return None

    return str(type_a), str(type_b)

def _gather_votes(class_a, class_b):
    for field_a, field_b in zip(class_a.fields, class_b.fields):
        vote = _get_vote_for_types(field_a.type, field_b.type)
        if vote is not None:
            yield vote
    
    for method_a, method_b in zip(class_a.methods, class_b.methods):
        vote = _get_vote_for_types(method_a.prototype.return_type, method_b.prototype.return_type)
        if vote is not None:
            yield vote
        
        for param_a, param_b in zip(method_a.prototype.parameters_type, method_b.prototype.parameters_type):
            vote = _get_vote_for_types(param_a, param_b)
            if vote is not None:
                yield vote

def map(classes_a, classes_b, only_obfuscated: bool=False, propagate: bool=True):
    logger.info(f'classes in input A: {len(classes_a)}')
    logger.info(f'classes in input B: {len(classes_b)}')

    encodings_a = [encode_class(cls) for cls in classes_a]
    encodings_b = [encode_class(cls) for cls in classes_b]

    mapping, reverse_mapping = heckel_diff(encodings_a, encodings_b)

    logger.info(f'heckel diff mapped classes: {len(mapping)}')

    if propagate:

        classes_mapping = {classes_a[k]: classes_b[v] for k, v in mapping.items()}
        votes = Counter(vote for class_a, class_b in classes_mapping.items() for vote in _gather_votes(class_a, class_b))

        logger.info(f'propagation votes: {len(votes)} ({votes.total()} total)')

    mapping = {classes_a[k].fullname: classes_b[v].fullname for k, v in mapping.items()}

    if propagate:

        mapped_a = set(mapping.keys())
        mapped_b = set(mapping.values())

        for class_a, class_b in sorted(votes, key=votes.get):
            if class_a in mapped_a or class_b in mapped_b:
                continue

            mapping[class_a] = class_b
            mapped_a.add(class_a)
            mapped_b.add(class_b)

        logger.info(f'propagation mapped classes: {len(mapping)}')

    if only_obfuscated:
        mapping = {k: v for k, v in mapping.items() if is_obfuscated_class_name(k)}

    return mapping

def _lief_type_to_enigma(type: DEX.Type) -> str:
    if type.type == DEX.Type.TYPES.CLASS:
        return str(type)
    if type.type == DEX.Type.TYPES.PRIMITIVE:
        return {
            DEX.Type.PRIMITIVES.BOOLEAN: 'Z',
            DEX.Type.PRIMITIVES.BYTE: 'B',
            DEX.Type.PRIMITIVES.CHAR: 'C',
            DEX.Type.PRIMITIVES.DOUBLE: 'D',
            DEX.Type.PRIMITIVES.FLOAT: 'F',
            DEX.Type.PRIMITIVES.INT: 'I',
            DEX.Type.PRIMITIVES.LONG: 'J',
            DEX.Type.PRIMITIVES.SHORT: 'S',
            DEX.Type.PRIMITIVES.VOID_T: 'V',
        }[type.value]
    return '[' * type.dim + _lief_type_to_enigma(type.underlying_array_type)

def _lief_prototype_to_enigma(prototype: DEX.Prototype) -> str:
    return f'({"".join([_lief_type_to_enigma(p) for p in prototype.parameters_type])}){_lief_type_to_enigma(prototype.return_type)}'

def deobfuscate(classes_a: List[DEX.Class], classes_b: List[DEX.Class], mapping: Dict[str, str], deobfuscation_mapping: EnigmaMapping) -> EnigmaMapping:
    enigma_classes = []
    for enigma_class in deobfuscation_mapping:
        old_name = f'L{enigma_class.name};'
        try:
            new_name = mapping[old_name]
        except KeyError:
            logger.warn(f'failed to map class {enigma_class.display_name or "?"} ({enigma_class.name})')
            continue

        original_enigma_fields = enigma_class.fields.copy()
        original_enigma_methods = {m for m in enigma_class.methods}
        enigma_class = EnigmaClass(new_name[1:-1], enigma_class.display_name)
        enigma_classes.append(enigma_class)

        class_a = [cls for cls in classes_a if cls.fullname == old_name][0]
        class_b = [cls for cls in classes_b if cls.fullname == new_name][0]

        fields = list(zip(class_a.fields, class_b.fields))
        for enigma_field in original_enigma_fields:
            try:
                field_a, field_b = [(f_a, f_b) for f_a, f_b in fields if f_a.name == enigma_field.name][0]
            except IndexError:
                logger.warn(f'failed to map field {enigma_field.display_name} in class {enigma_class.display_name or "?"} ({enigma_class.name})')
                continue

            enigma_class.fields.append(EnigmaField(field_b.name, enigma_field.display_name, _lief_type_to_enigma(field_b.type)))

        for method_a, method_b in zip(class_a.methods, class_b.methods):
            for enigma_method in original_enigma_methods:
                if enigma_method.name == method_a.name and enigma_method.prototype == _lief_prototype_to_enigma(method_a.prototype):
                    break
            else:
                continue

            original_enigma_methods.remove(enigma_method)

            enigma_class.methods.append(EnigmaMethod(method_b.name, enigma_method.display_name, _lief_prototype_to_enigma(method_b.prototype)))

        for enigma_method in original_enigma_methods:
            logger.warn(f'failed to map method {enigma_method.display_name} in class {enigma_class.display_name or "?"} ({enigma_class.name})')

    return EnigmaMapping(enigma_classes)
