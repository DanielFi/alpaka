# Alpaka

Alpaka is a tool for mapping classes between different versions of the same APK.

## Usage

Output a JSON mapping from `A.apk` to `B.apk`:

```console
> alpaka map A.apk B.apk1
{
    "LX/003;": "LX/003;",
    "LX/004;": "LX/004;",
    "LX/005;": "LX/005;",
    "LX/006;": "LX/006;",
...
```

You can also `--deobfuscation` to supply an enigma mapping file, and it will be mapped to the new version:

```console
> alpaka map --deobfuscation A.mapping --only-obfuscated A.apk B.apk1 > B.mapping
```

These enigma mapping file can then be imported into Jadx, in order to keep manual renamings from previous versions!