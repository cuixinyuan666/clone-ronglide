# -*- coding: utf-8 -*-
import time
import win32api
from PIL import ImageGrab

# hover a few x positions on the current chart and save the tooltip plus the axis
xs = [140, 180, 230, 320]
for i, x in enumerate(xs):
    win32api.SetCursorPos((x, 400))
    time.sleep(0.55)
    im = ImageGrab.grab()
    im.crop((x, 280, x + 380, 520)).save(
        rf"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\tip_{i}.png"
    )
im = ImageGrab.grab()
im.crop((60, 1100, 900, 1240)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\axis_now.png"
)
print("tips")
