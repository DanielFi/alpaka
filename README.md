# Alpaka

[![PyPI - Version](https://img.shields.io/pypi/v/alpaka-re.svg)](https://pypi.org/project/alpaka-re)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/alpaka-re.svg)](https://pypi.org/project/alpaka-re)

-----

Alpaka is a command-line tool designed for mapping classes across different
versions of the same APK. This is particularly useful for reverse engineering,
allowing you to track class renames and changes across different builds, and
preserving manual deobfuscation efforts.

## Features

* Class Mapping: Generates a JSON mapping of classes from one APK version to another.

* Deobfuscation Migration: Migrate existing Enigma deobfuscation
  mapping files to new APK versions, helping maintain your renaming efforts
  in tools like Jadx.

## Installation

```console
git clone https://github.com/DanielFi/alpaka
pip install ./alpaka
```

## Usage

### Basic Class Mapping

Output a JSON mapping from `A.apk` (older version) to `B.apk` (newer version).
This will show how classes in `A.apk` correspond to classes in `B.apk`.

```console
> alpaka map A.apk B.apk1
{
    "LX/003;": "LX/003;",
    "LX/004;": "LX/004;",
    "LX/005;": "LX/005;",
    "LX/006;": "LX/006;",
...
```

### Migrating Deobfuscation Mappings Across Versions

If you have an Enigma mapping file (e.g., `A.mapping`) for `A.apk`, you can use
Alpaka to generate a new mapping file (`B.mapping`) that applies your existing
renames to `B.apk`. This is incredibly useful for maintaining your manual
deobfuscation work when a new version of the APK is released.

The generated `B.mapping` file can then be imported into tools like Jadx to preserve your manual renamings!

```console
> alpaka map --deobfuscation A.mapping --only-obfuscated A.apk B.apk1 > B.mapping
```

### Advanced Options

The `map` command supports several options to fine-tune its behavior:

* `--only-obfuscated`: Prevents Alpaka from creating unnecessary mappings
  between unobfuscated classes.
* `--no-propagation`: Only run the first analysis stage. Usually leads to more
  accurate results but fewer mappings overall.

## License

Alpaka is distributed under the terms of the [MIT](https://spdx.org/licenses/MIT.html) license.
