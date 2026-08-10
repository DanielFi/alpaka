import itertools
import logging
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from lief import DEX

logger = logging.getLogger(__name__)

_DEX_CACHE: list[DEX.File] = []  # hack to prevent segfaults (lief objects become invalid if the DEX.File is freed)

EXTERNAL_CLASS_INDEX = 0xFFFFFFFF


def get_dex(dex_path: str) -> DEX.File:
    dex = DEX.parse(dex_path)
    assert dex is not None
    _DEX_CACHE.append(dex)
    return dex


def extract_dexs_from_apk(apk_path: str) -> list[DEX.File]:
    dexs = []
    tmp_dir = TemporaryDirectory()

    with ZipFile(apk_path) as z:
        namelist = z.namelist()
        for i in itertools.count(start=1):
            dex_filename = "classes" + ("" if i == 1 else str(i)) + ".dex"
            if dex_filename not in namelist:
                logger.info(f"APK {apk_path} has {i - 1} dex files")
                break

            dexs.append(get_dex(z.extract(dex_filename, tmp_dir.name)))

    return dexs


def get_classes_from_dexs(dexs: list[DEX.File]) -> list[DEX.Class]:
    return [
        cls
        for dex in dexs
        for cls in sorted(dex.classes, key=lambda cls: cls.index)
        if cls.index != EXTERNAL_CLASS_INDEX
    ]
