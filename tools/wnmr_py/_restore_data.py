# -*- coding: utf-8 -*-
import shutil
src = r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\install_backup\Dat\His\02\1\600000.1"
dst = r"D:\a_ronglide\缠中说禅\Dat\His\02\1\600000.1"
shutil.copy2(src, dst)
import os
print("restored", os.path.getsize(dst))
