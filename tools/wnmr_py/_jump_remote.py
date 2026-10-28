# -*- coding: utf-8 -*-
"""Set the jump date inside the target process, then confirm."""
import ctypes
import time
import win32api
import win32gui
from ctypes import wintypes
from PIL import ImageGrab

ctypes.windll.user32.SetProcessDPIAware()
u32 = ctypes.windll.user32
k32 = ctypes.windll.kernel32
u32.GetMenuStringW.argtypes = [wintypes.HMENU, wintypes.UINT, wintypes.LPWSTR, ctypes.c_int, wintypes.UINT]
u32.GetMenuStringW.restype = ctypes.c_int
u32.GetMenuItemCount.argtypes = [wintypes.HMENU]
u32.GetMenuItemCount.restype = ctypes.c_int
u32.GetMenuItemRect.argtypes = [wintypes.HWND, wintypes.HMENU, wintypes.UINT, ctypes.POINTER(wintypes.RECT)]
u32.GetMenuItemRect.restype = wintypes.BOOL
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenProcess.restype = wintypes.HANDLE
k32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
k32.VirtualAllocEx.restype = wintypes.LPVOID
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.restype = wintypes.BOOL
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.ReadProcessMemory.restype = wintypes.BOOL
k32.VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
k32.VirtualFreeEx.restype = wintypes.BOOL
Send = u32.SendMessageW
Send.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
Send.restype = wintypes.LPARAM

DTM_GETSYSTEMTIME = 0x1001
DTM_SETSYSTEMTIME = 0x1002
GDT_VALID = 0
MN_GETHMENU = 0x01E1
MF_BYPOSITION = 0x0400

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wintypes.WORD), ("wMonth", wintypes.WORD),
        ("wDayOfWeek", wintypes.WORD), ("wDay", wintypes.WORD),
        ("wHour", wintypes.WORD), ("wMinute", wintypes.WORD),
        ("wSecond", wintypes.WORD), ("wMilliseconds", wintypes.WORD),
    ]

def blockers():
    def cb(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return
        cls = win32gui.GetClassName(hwnd)
        if cls in ("CLASSNAME_RLD_CZSC_MAINAPP", "Progman", "Shell_TrayWnd", "WorkerW", "#32770"):
            return
        if win32gui.GetParent(hwnd):
            return
        r = win32gui.GetWindowRect(hwnd)
        if r[2] - r[0] > 500 and r[3] - r[1] > 300 and -200 < r[0] < 500:
            import win32con
            win32gui.ShowWindow(hwnd, win32con.SW_MINIMIZE)
    win32gui.EnumWindows(cb, None)

def find_main():
    res = []
    win32gui.EnumWindows(lambda h, _: res.append(h) if win32gui.IsWindowVisible(h) and win32gui.GetClassName(h) == "CLASSNAME_RLD_CZSC_MAINAPP" else None, None)
    return res[0]

def fg(h):
    f = u32.GetForegroundWindow()
    t1 = ctypes.windll.kernel32.GetCurrentThreadId()
    t2 = u32.GetWindowThreadProcessId(f, None)
    u32.AttachThreadInput(t1, t2, True)
    try:
        u32.SwitchToThisWindow(h, True)
    finally:
        u32.AttachThreadInput(t1, t2, False)

def click(x, y, wait=0.3):
    win32api.SetCursorPos((int(x), int(y)))
    time.sleep(0.06)
    win32api.mouse_event(2, 0, 0, 0, 0)
    time.sleep(0.03)
    win32api.mouse_event(4, 0, 0, 0, 0)
    time.sleep(wait)

blockers()
main = find_main()
fg(main)
time.sleep(0.25)
# close the stuck quote popup, then right-click a clear candle
win32api.keybd_event(0x1B, 0, 0, 0)
time.sleep(0.03)
win32api.keybd_event(0x1B, 0, 2, 0)
time.sleep(0.35)
click(1300, 500, 0.25)
win32api.SetCursorPos((1300, 500))
time.sleep(0.08)
win32api.mouse_event(8, 0, 0, 0, 0)
time.sleep(0.04)
win32api.mouse_event(16, 0, 0, 0, 0)
time.sleep(0.45)
target = None
def find_popup(hwnd, _):
    global target
    if not (win32gui.IsWindowVisible(hwnd) and win32gui.GetClassName(hwnd) == "#32768"):
        return
    hmenu = u32.SendMessageW(hwnd, MN_GETHMENU, 0, 0)
    n = u32.GetMenuItemCount(hmenu)
    for i in range(max(n, 0)):
        buf = ctypes.create_unicode_buffer(64)
        u32.GetMenuStringW(hmenu, i, buf, 64, MF_BYPOSITION)
        if buf.value == "跳转到":
            rc = wintypes.RECT()
            u32.GetMenuItemRect(hwnd, hmenu, i, ctypes.byref(rc))
            target = ((rc.left + rc.right) // 2, (rc.top + rc.bottom) // 2)
win32gui.EnumWindows(find_popup, None)
print("item", target)
if not target:
    ImageGrab.grab().crop((1100, 350, 1700, 1000)).save(
        r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\no_menu2.png"
    )
    raise SystemExit(2)
click(*target, 0.5)

dlg = picker = ok = None
def find_dlg(hwnd, _):
    global dlg
    if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == "跳转到":
        dlg = hwnd
win32gui.EnumWindows(find_dlg, None)
def ch(c, _):
    global picker, ok
    cls = win32gui.GetClassName(c)
    if cls == "SysDateTimePick32":
        picker = c
    if cls == "Button" and win32gui.GetWindowText(c) == "确定":
        ok = c
win32gui.EnumChildWindows(dlg, ch, None)
print("picker", hex(picker), "ok", hex(ok))

pid = wintypes.DWORD()
u32.GetWindowThreadProcessId(picker, ctypes.byref(pid))
hproc = k32.OpenProcess(0x1F0FFF, False, pid.value)
print("pid", pid.value, "proc", hproc)
st = SYSTEMTIME(2017, 8, 4, 10, 0, 0, 0, 0)  # 2017-08-10 was Thursday
remote = k32.VirtualAllocEx(hproc, None, 64, 0x3000, 0x04)
print("remote", hex(remote or 0))
written = ctypes.c_size_t()
okw = k32.WriteProcessMemory(hproc, remote, ctypes.byref(st), ctypes.sizeof(st), ctypes.byref(written))
print("write", okw, written.value)
ret = Send(picker, DTM_SETSYSTEMTIME, GDT_VALID, remote)
print("set", ret)
# read back into the same remote buffer
ret2 = Send(picker, DTM_GETSYSTEMTIME, 0, remote)
got = SYSTEMTIME()
k32.ReadProcessMemory(hproc, remote, ctypes.byref(got), ctypes.sizeof(got), ctypes.byref(written))
print("get", ret2, got.wYear, got.wMonth, got.wDay)
k32.VirtualFreeEx(hproc, remote, 0, 0x8000)
k32.CloseHandle(hproc)
time.sleep(0.2)
pr = win32gui.GetWindowRect(picker)
ImageGrab.grab().crop((pr[0] - 180, pr[1] - 40, pr[2] + 20, pr[3] + 20)).save(
    r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump_set.png"
)
r = win32gui.GetWindowRect(ok)
click((r[0] + r[2]) // 2, (r[1] + r[3]) // 2, 1.2)
im = ImageGrab.grab()
im.crop((60, 900, 1600, 1300)).save(r"D:\a_ronglide\clone-ronglide\tools\wnmr_py\_shots\jump_remote_axis.png")
print("dlg", win32gui.IsWindow(dlg))
