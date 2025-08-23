import itertools
import logging
from tempfile import TemporaryDirectory
from typing import List
from zipfile import ZipFile

import lief.DEX as DEX


logger = logging.getLogger(__name__)

_DEX_CACHE = [] # hack to prevent segfaults (lief objects become invalid if the DEX.File is freed)

def get_dex(dex_path: str) -> List[DEX.File]:
    dex = DEX.parse(dex_path)
    _DEX_CACHE.append(dex)
    return dex

def extract_dexs_from_apk(apk_path: str) -> List[DEX.File]:
    dexs = []
    tmp_dir = TemporaryDirectory()

    with ZipFile(apk_path) as z:
        namelist = z.namelist()
        for i in itertools.count(start=1):
            dex_filename = 'classes' + ('' if i == 1 else str(i)) + '.dex'
            if (dex_filename not in namelist):
                logger.info(f'APK {apk_path} has {i-1} dex files')
                break

            dexs.append(get_dex(z.extract(dex_filename, tmp_dir.name)))

    return dexs

def get_classes_from_dexs(dexs: List[DEX.File]) -> List[DEX.Class]:
    return [cls for dex in dexs for cls in sorted(dex.classes, key=lambda cls: cls.index) if cls.index != 4294967295]

def get_methods_from_dexs(dexs: List[DEX.File]) -> List[DEX.Method]:
    return [mth for dex in dexs for mth in dex.methods if mth.cls.index != 4294967295]
