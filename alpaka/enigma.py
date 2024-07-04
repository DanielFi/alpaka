from typing import Iterable, List, Optional
from pathlib import Path
import re


CLASS_PATTERN = re.compile(r'CLASS (\S+)(?: (\S+))?')
FIELD_PATTERN = re.compile(r'\tFIELD (\S+) (\S+) (\S+)')
METHOD_PATTERN = re.compile(r'\tMETHOD (\S+) (\S+) (\S+)')


class EnigmaField:

    def __init__(self, name: str, display_name: str, type: str):
        self.name = name
        self.display_name = display_name
        self.type = type

    def __str__(self) -> str:
        return f'FIELD {self.name} {self.display_name} {self.type}'

class EnigmaMethod:

    def __init__(self, name: str, display_name: str, prototype: str):
        self.name = name
        self.display_name = display_name
        self.prototype = prototype

    def __str__(self) -> str:
        return f'METHOD {self.name} {self.display_name} {self.prototype}'

class EnigmaClass:

    def __init__(self, name: str, display_name: Optional[str]=None):
        self.name = name
        self.display_name = display_name
        self.fields: List[EnigmaField] = []
        self.methods: List[EnigmaMethod] = []

    def __str__(self) -> str:
        result = [f'CLASS {self.name} {self.display_name or ""}']
        for field in self.fields:
            result.append(f'\t{str(field)}')
        for method in self.methods:
            result.append(f'\t{str(method)}')
        return '\n'.join(result)

class EnigmaMapping:

    def __init__(self, classes: List[EnigmaClass]):
        self.classes = classes

    def __str__(self) -> str:
        return '\n'.join(str(cls) for cls in self.classes)

    def __iter__(self) -> Iterable[EnigmaClass]:
        return iter(self.classes)

    @classmethod
    def parse(cls, path: str) -> 'EnigmaMapping':
        classes = []

        with open(path, 'r') as f:
            current_class = None
            for line in f.readlines():
                if match := CLASS_PATTERN.match(line):
                    current_class = EnigmaClass(match.group(1), match.group(2))
                    classes.append(current_class)
                elif match := FIELD_PATTERN.match(line):
                    current_class.fields.append(EnigmaField(match.group(1), match.group(2), match.group(3)))
                elif match := METHOD_PATTERN.match(line):
                    current_class.methods.append(EnigmaMethod(match.group(1), match.group(2), match.group(3)))

        return cls(classes)
