"""e2e_gui.py - tiny DPI-aware GUI helper for the client (physical pixel coords).
Commands:
  shot <name>            capture full screen to tools/_e2e_<name>.png
  click <x> <y> [d]      move cursor, left click (append d for double click); physical px
"""
import ctypes
import sys
import time

from PIL import ImageGrab

u32 = ctypes.windll.user32
u32.SetProcessDPIAware()

TOOLS = r"D:\a_ronglide\clone-ronglide\tools"


def shot(name):
    time.sleep(0.3)
    img = ImageGrab.grab()
    path = TOOLS + r"\_e2e_%s.png" % name
    img.save(path)
    print("shot", path, img.size)


def click(x, y, double=False):
    u32.SetCursorPos(int(x), int(y))
    time.sleep(0.15)
    u32.mouse_event(2, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.08)
    u32.mouse_event(4, 0, 0, 0, 0)  # LEFTUP
    if double:
        time.sleep(0.05)
        u32.mouse_event(2, 0, 0, 0, 0)
        time.sleep(0.08)
        u32.mouse_event(4, 0, 0, 0, 0)
    time.sleep(0.7)
    print("clicked", x, y, "double=" + str(double))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "shot":
        shot(sys.argv[2])
    elif cmd == "click":
        click(int(sys.argv[2]), int(sys.argv[3]),
              double=(len(sys.argv) > 4 and sys.argv[4] == "d"))
    else:
        print(__doc__)
        sys.exit(2)
