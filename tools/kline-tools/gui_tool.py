# -*- coding: utf-8 -*-
"""融立德图表 GUI 自动化辅助工具（启动/枚举窗口/截图/发键）。
用法:
  python gui_tool.py list                 # 列出可见窗口
  python gui_tool.py launch [wait秒]      # 启动 MainApp 并等待
  python gui_tool.py shot <out.png>       # 全屏截图
  python gui_tool.py shotwin <h> <out>    # 指定窗口截图
  python gui_tool.py activate <h>         # 激活窗口
  python gui_tool.py keys <text>          # 向当前前台窗口发键
  python gui_tool.py close                # 关闭 MainApp
"""
import sys, os, time, subprocess
import win32gui, win32con, win32api
from PIL import ImageGrab

APP_DIR = r"D:\a_ronglide\缠中说禅"
APP = os.path.join(APP_DIR, "MainApp.exe")


def list_windows():
    out = []
    def cb(h, _):
        if win32gui.IsWindowVisible(h):
            t = win32gui.GetWindowText(h)
            if t.strip():
                out.append((h, t, win32gui.GetClassName(h), win32gui.GetWindowRect(h)))
    win32gui.EnumWindows(cb, None)
    return out


def shot(path):
    im = ImageGrab.grab()
    im.save(path)
    return path


def shot_win(h, path):
    l, t, r, b = win32gui.GetWindowRect(h)
    im = ImageGrab.grab(bbox=(l, t, r, b))
    im.save(path)
    return path


def send_text(txt, delay=0.05):
    """通过 keybd_event 发送按键（支持数字字母与回车）"""
    VK = {c: ord(c.upper()) for c in "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"}
    for ch in txt:
        if ch == "\n" or ch == "\r":
            vk = 0x0D
        elif ch in VK:
            vk = VK[ch]
        else:
            continue
        win32api.keybd_event(vk, 0, 0, 0)
        time.sleep(0.02)
        win32api.keybd_event(vk, 0, win32con.KEYEVENTF_KEYUP, 0)
        time.sleep(delay)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    if cmd == "list":
        for h, t, c, r in list_windows():
            print(f"{h:12d} | {t[:64]:64s} | {c:24s} | {r}")
    elif cmd == "launch":
        os.chdir(APP_DIR)
        p = subprocess.Popen([APP])
        wait = int(sys.argv[2]) if len(sys.argv) > 2 else 40
        print("pid", p.pid, "waiting", wait)
        time.sleep(wait)
        print("ready")
    elif cmd == "shot":
        print("saved", shot(sys.argv[2]))
    elif cmd == "shotwin":
        print("saved", shot_win(int(sys.argv[2]), sys.argv[3]))
    elif cmd == "activate":
        h = int(sys.argv[2])
        win32gui.ShowWindow(h, win32con.SW_RESTORE)
        try:
            win32gui.SetForegroundWindow(h)
        except Exception as e:
            print("SetForegroundWindow warn:", e)
        print("activated", h)
    elif cmd == "keys":
        send_text(sys.argv[2])
        print("sent", sys.argv[2])
    elif cmd == "click":
        x, y = int(sys.argv[2]), int(sys.argv[3])
        win32api.SetCursorPos((x, y))
        time.sleep(0.2)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
        time.sleep(0.05)
        win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        print("clicked", x, y)
    elif cmd == "dblclick":
        x, y = int(sys.argv[2]), int(sys.argv[3])
        win32api.SetCursorPos((x, y))
        time.sleep(0.2)
        for _ in range(2):
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            time.sleep(0.03)
            win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
            time.sleep(0.08)
        print("dblclicked", x, y)
    elif cmd == "paste":
        import win32clipboard
        text = sys.argv[2]
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text, win32clipboard.CF_UNICODETEXT)
        win32clipboard.CloseClipboard()
        time.sleep(0.4)
        win32api.keybd_event(0x11, 0, 0, 0)
        win32api.keybd_event(0x56, 0, 0, 0)
        time.sleep(0.06)
        win32api.keybd_event(0x56, 0, win32con.KEYEVENTF_KEYUP, 0)
        win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)
        print("pasted", text)
    elif cmd == "dlg0508":
        title = "导入0508历史数据"
        h = win32gui.FindWindow(None, title)
        if not h:
            print("dialog not found")
        else:
            path = sys.argv[2]
            state = {"edit": None, "btn": None, "close": None}
            def cb(ch, _):
                cls = win32gui.GetClassName(ch)
                txt = win32gui.GetWindowText(ch)
                if cls == "Edit":
                    state["edit"] = ch
                if cls == "Button" and txt == "导入":
                    state["btn"] = ch
                if cls == "Button" and txt == "关闭":
                    state["close"] = ch
            win32gui.EnumChildWindows(h, cb, None)
            win32gui.SendMessage(state["edit"], win32con.WM_SETTEXT, 0, path)
            time.sleep(0.4)
            win32gui.SendMessage(state["btn"], win32con.BM_CLICK, 0, 0)
            print("0508 import triggered:", path, "edit=", state["edit"], "btn=", state["btn"])
    elif cmd == "dlg0508close":
        h = win32gui.FindWindow(None, "导入0508历史数据")
        if h:
            state = {"close": None}
            def cb2(ch, _):
                if win32gui.GetClassName(ch) == "Button" and win32gui.GetWindowText(ch) == "关闭":
                    state["close"] = ch
            win32gui.EnumChildWindows(h, cb2, None)
            if state["close"]:
                win32gui.SendMessage(state["close"], win32con.BM_CLICK, 0, 0)
            print("closed dialog")
        else:
            print("no dialog")
    elif cmd == "dlg0508info":
        h = win32gui.FindWindow(None, "导入0508历史数据")
        if h:
            def cb3(ch, _):
                cls = win32gui.GetClassName(ch)
                txt = win32gui.GetWindowText(ch)
                r = win32gui.GetWindowRect(ch)
                print(f"  {cls:22s} {r} {txt!r}")
            win32gui.EnumChildWindows(h, cb3, None)
        else:
            print("no dialog")
    elif cmd == "close":
        os.system("taskkill /IM MainApp.exe /F")
        print("closed")
    else:
        print("unknown cmd", cmd)


main()
