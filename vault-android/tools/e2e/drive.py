# Minimal adb + uiautomator driver for the vault app. Refuses to tap, scroll or type unless the vault app
# is in the foreground, so it never touches another app on the device.
# Drives the isol8 vault app on a test device over adb, reading the screen via uiautomator.
import re, subprocess, sys, time, xml.etree.ElementTree as ET
ADB = [sys.argv[1], "-s", sys.argv[2]]
def adb(*a, check=True): return subprocess.run(ADB + list(a), capture_output=True, text=True, check=check).stdout
def nodes():
    for _ in range(5):
        adb("shell", "uiautomator", "dump", "/sdcard/u.xml", check=False)
        x = adb("shell", "cat", "/sdcard/u.xml", check=False)
        if x.startswith("<?xml"): break
        time.sleep(1)
    out = []
    for n in ET.fromstring(x[x.index("<?xml"):]).iter("node"):
        b = [int(v) for v in re.findall(r"\d+", n.get("bounds", "[0,0][0,0]"))]
        out.append({"text": n.get("text", ""), "cls": n.get("class", ""), "enabled": n.get("enabled") == "true", "b": b})
    return out
def ours():
    out = adb("shell", "dumpsys", "activity", "activities", check=False)
    return any("topResumedActivity" in l and "app.isol8.vault/" in l for l in out.splitlines())
def guard():
    if not ours(): raise SystemExit("ABORT: the vault app isn't in the foreground; not touching anything else on the device.")
def texts(): return [n["text"] for n in nodes() if n["text"]]
def find(label, exact=True):
    hits = [n for n in nodes() if ((n["text"] == label) if exact else (label in n["text"]))]
    hits.sort(key=lambda n: 0 if n["cls"].endswith("Button") else 1)  # prefer buttons over same-text titles
    return hits[0] if hits else None
def tap(label, exact=True, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        n = find(label, exact)
        if n:
            x1, y1, x2, y2 = n["b"]
            if y2 > y1:
                guard(); adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)); time.sleep(0.4); return n
        guard(); adb("shell", "input", "swipe", "1000", "900", "1000", "400", "200"); time.sleep(0.5)  # scroll and retry
    raise SystemExit(f"FAIL: couldn't find {label!r}. Screen: {texts()}")
def wait_for(label, exact=False, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if find(label, exact): return
        time.sleep(1.5)
    raise SystemExit(f"FAIL: timed out waiting for {label!r}. Screen: {texts()}")
def type_into(hint, value):
    n = tap(hint); guard(); adb("shell", "input", "text", value); time.sleep(0.3)
def check(cond, msg): print(("PASS " if cond else "FAIL ") + msg); (None if cond else sys.exit(1))
