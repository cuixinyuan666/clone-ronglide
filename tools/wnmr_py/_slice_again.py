# -*- coding: utf-8 -*-
import shutil

src = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\install_backup\Dat\His\02\1\600000.1"
dst = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"
data = open(src, "rb").read()
lo, hi = 35180, 35520
chunk = data[:68] + data[68 + lo * 36:68 + hi * 36]
open(dst, "wb").write(chunk)
print("bars", (len(chunk) - 68) // 36)
