import json
import logging

import click

from .core import deobfuscate, match_classes
from .enigma import EnigmaMapping
from .extraction import extract_dexs_from_apk, get_classes_from_dexs

logger = logging.getLogger(__name__)


@click.group()
@click.option("-v", "--verbose", is_flag=True)
def main(verbose: bool) -> None:
    if verbose:
        logging.basicConfig(level=logging.INFO)


@main.command()
@click.option("--only-obfuscated", is_flag=True)
@click.option("--no-propagation", is_flag=True)
@click.option("--deobfuscation", type=click.Path(exists=True))
@click.argument("input_a", type=click.Path(exists=True))
@click.argument("input_b", type=click.Path(exists=True))
def match(only_obfuscated: bool, no_propagation: bool, deobfuscation: str | None, input_a: str, input_b: str) -> None:
    deobfuscation_mapping = EnigmaMapping.parse(deobfuscation) if deobfuscation is not None else None

    dexs_a = extract_dexs_from_apk(input_a)
    dexs_b = extract_dexs_from_apk(input_b)

    mapping = match_classes(dexs_a, dexs_b, only_obfuscated=only_obfuscated, propagate=not no_propagation)

    mapping = {k.fullname: v.fullname for k, v in mapping.items()}

    if deobfuscation_mapping is None:
        click.echo(json.dumps(mapping, indent=4))
    else:
        click.echo(
            deobfuscate(get_classes_from_dexs(dexs_a), get_classes_from_dexs(dexs_b), mapping, deobfuscation_mapping)
        )


if __name__ == "__main__":
    main()
