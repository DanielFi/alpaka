import itertools
import logging
from tempfile import TemporaryDirectory
from typing import List
from zipfile import ZipFile

import lief.DEX as DEX


logger = logging.getLogger(__name__)

_DEX_CACHE = [] # hack to prevent segfaults (lief objects become invalid if the DEX.File is freed)

def extract_classes_from_dex(dex_path: str) -> List[DEX.Class]:
    dex = DEX.parse(dex_path)
    _DEX_CACHE.append(dex)
    return list(sorted(dex.classes, key=lambda c: c.index))

def extract_classes_from_apk(apk_path: str) -> List[DEX.Class]:
    classes = []
    tmp_dir = TemporaryDirectory()

    with ZipFile(apk_path) as z:
        namelist = z.namelist()
        for i in itertools.count(start=1):
            dex_filename = 'classes' + ('' if i == 1 else str(i)) + '.dex'
            if (dex_filename not in namelist):
                logger.info(f'APK {apk_path} has {i-1} dex files')
                break

            classes.extend(extract_classes_from_dex(z.extract(dex_filename, tmp_dir.name)))

    return classes
