import re
from collections.abc import Iterator
from os import PathLike
from pathlib import Path

CLASS_PATTERN = re.compile(r"CLASS (\S+)(?: (\S+))?")
FIELD_PATTERN = re.compile(r"\tFIELD (\S+) (\S+) (\S+)")
METHOD_PATTERN = re.compile(r"\tMETHOD (\S+) (\S+) (\S+)")


class EnigmaField:
    def __init__(self, name: str, display_name: str, field_type: str) -> None:
        self.name = name
        self.display_name = display_name
        self.type = field_type

    def __str__(self) -> str:
        return f"FIELD {self.name} {self.display_name} {self.type}"


class EnigmaMethod:
    def __init__(self, name: str, display_name: str, prototype: str) -> None:
        self.name = name
        self.display_name = display_name
        self.prototype = prototype

    def __str__(self) -> str:
        return f"METHOD {self.name} {self.display_name} {self.prototype}"


class EnigmaClass:
    def __init__(self, name: str, display_name: str | None = None) -> None:
        self.name = name
        self.display_name = display_name
        self.fields: list[EnigmaField] = []
        self.methods: list[EnigmaMethod] = []

    def __str__(self) -> str:
        result = [f"CLASS {self.name} {self.display_name or ''}"]
        for field in self.fields:
            result.append(f"\t{field!s}")
        for method in self.methods:
            result.append(f"\t{method!s}")
        return "\n".join(result)


class EnigmaMapping:
    def __init__(self, classes: list[EnigmaClass]) -> None:
        self.classes = classes

    def __str__(self) -> str:
        return "\n".join(str(cls) for cls in self.classes)

    def __iter__(self) -> Iterator[EnigmaClass]:
        return iter(self.classes)

    @classmethod
    def parse(cls, path: PathLike[str] | str) -> "EnigmaMapping":
        classes: list[EnigmaClass] = []

        with Path(path).open() as f:
            current_class: EnigmaClass | None = None
            for line in f:
                if match := CLASS_PATTERN.match(line):
                    current_class = EnigmaClass(match.group(1), match.group(2))
                    classes.append(current_class)
                elif match := FIELD_PATTERN.match(line):
                    assert current_class is not None
                    current_class.fields.append(EnigmaField(match.group(1), match.group(2), match.group(3)))
                elif match := METHOD_PATTERN.match(line):
                    assert current_class is not None
                    current_class.methods.append(EnigmaMethod(match.group(1), match.group(2), match.group(3)))

        return cls(classes)
