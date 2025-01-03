import click
import logging
import json

from .core import map as map_apks, deobfuscate as map_renaming
from .enigma import EnigmaMapping
from .extraction import extract_classes_from_apk


logger = logging.getLogger(__name__)

@click.group()
@click.option('-v', '--verbose', is_flag=True)
def main(verbose):
    if verbose:
        logging.basicConfig(level=logging.INFO)


@main.command()
@click.option('--only-obfuscated', is_flag=True)
@click.option('--no-propagation', is_flag=True)
@click.option('--deobfuscation', type=click.Path(exists=True))
@click.argument('input_a', type=click.Path(exists=True))
@click.argument('input_b', type=click.Path(exists=True))
def map(only_obfuscated, no_propagation, deobfuscation, input_a, input_b):
    if deobfuscation is not None:
        deobfuscation = EnigmaMapping.parse(deobfuscation)

    classes_a = [cls for cls in extract_classes_from_apk(input_a) if cls.index != 4294967295]
    classes_b = [cls for cls in extract_classes_from_apk(input_b) if cls.index != 4294967295]

    mapping = map_apks(classes_a, classes_b, only_obfuscated=only_obfuscated, propagate=not no_propagation)

    if deobfuscation is None:
        click.echo(json.dumps(mapping, indent=4))
    else:
        click.echo(map_renaming(classes_a, classes_b, mapping, deobfuscation))


if __name__ == '__main__':
    main()
