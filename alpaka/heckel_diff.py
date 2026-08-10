from collections.abc import Hashable
from dataclasses import dataclass


@dataclass
class Symbol:
    old_count: int
    new_count: int
    olno: int


class SymbolTable:
    def __init__(self) -> None:
        self.entries: dict[Hashable, Symbol] = {}

    def insert_old(self, symbol: Hashable, line: int) -> None:
        if symbol in self.entries:
            self.entries[symbol].old_count += 1
            self.entries[symbol].olno = line
        else:
            self.entries[symbol] = Symbol(1, 0, line)

    def insert_new(self, symbol: Hashable) -> None:
        if symbol in self.entries:
            self.entries[symbol].new_count += 1
        else:
            self.entries[symbol] = Symbol(0, 1, 0)

    def __getitem__(self, symbol: Hashable) -> Symbol:
        return self.entries[symbol]


def diff(old: list[Hashable], new: list[Hashable]) -> tuple[dict[int, int], dict[int, int]]:  # noqa: C901

    symbol_table = SymbolTable()

    mapping: dict[int, int] = {}
    reverse_mapping: dict[int, int] = {}

    # Pass 1
    for symbol in new:
        symbol_table.insert_new(symbol)

    # Pass 2
    for line, symbol in enumerate(old):
        symbol_table.insert_old(symbol, line)

    # Pass 3
    for line, symbol in enumerate(new):
        entry: Symbol = symbol_table[symbol]
        if entry.old_count == 1 and entry.new_count == 1:
            mapping[entry.olno] = line
            reverse_mapping[line] = entry.olno

    # Pass 4
    for line, symbol in list(enumerate(new))[1:]:
        if line - 1 not in reverse_mapping:
            continue

        maybe_old_line = reverse_mapping[line - 1] + 1

        if maybe_old_line >= len(old) or maybe_old_line in mapping:
            continue

        if old[maybe_old_line] == symbol:
            mapping[maybe_old_line] = line
            reverse_mapping[line] = maybe_old_line

    # Pass 5
    for line, symbol in list(reversed(list(enumerate(new))))[:1]:
        if line + 1 not in reverse_mapping:
            continue

        maybe_old_line = reverse_mapping[line + 1] - 1

        if maybe_old_line in mapping:
            continue

        if old[maybe_old_line] == symbol:
            mapping[maybe_old_line] = line
            reverse_mapping[line] = maybe_old_line

    return mapping, reverse_mapping
