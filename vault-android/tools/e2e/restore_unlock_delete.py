# End-to-end test on a TEST device: restore the public test phrase, unlock (wrong, then right),
# check leaving locks the vault, then delete. Usage: python3 -I restore_unlock_delete.py <adb> <serial>
# Needs: the vault app open on Home, a screen lock set, no vault yet, and the screen kept awake.
import os
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "drive.py")).read())
PHRASE = ["abandon"] * 11 + ["about"]          # public BIP39 test phrase
EXPECTED = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
PASS = "isol8-e2e-test-pass"
hidden_words = None

def buttons(): return [n for n in nodes() if n["cls"].endswith("Button")]
def tap_node(n):
    x1, y1, x2, y2 = n["b"]; guard(); adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2)); time.sleep(0.4)
def edit_fields(): return [n for n in nodes() if n["cls"].endswith("EditText")]

wait_for("OFFLINE STATUS"); guard()
if find("Development override: ignore offline checks"): tap("Development override: ignore offline checks")
check(find("Restore from a recovery phrase") is not None, "home offers create/restore (screen lock set, no vault yet, override on)")

# ---- restore through the app's own picker
tap("Restore from a recovery phrase"); tap("12 words")
for i, word in enumerate(PHRASE):
    wait_for(f"Word {i+1} of 12", exact=True)
    for c in word[:4]: tap(c)                 # 4 letters identify any BIP39 English word
    ns = buttons()
    match = [n for n in ns if n["text"] == word]
    if match: hidden_words = False; tap_node(match[0])
    else:
        hidden_words = True
        tap_node(ns[0])                       # single candidate is the first button, before the letter keys
wait_for("Check your words", exact=True)
review = [n["text"] for n in buttons()][:12]
tap("Continue")
wait_for("Is this your wallet?", exact=True)
check(find(EXPECTED) is not None, f"address preview from the restored phrase is {EXPECTED}")

# ---- set the vault passphrase and save
tap("Yes, continue"); wait_for("Set a vault passphrase", exact=True)
f = edit_fields(); check(len(f) == 2, "two passphrase fields")
tap_node(f[0]); guard(); adb("shell", "input", "text", PASS)
tap_node(edit_fields()[1]); guard(); adb("shell", "input", "text", PASS)
tap("Restore vault")
wait_for("Vault restored", exact=True, timeout=90)
check(find(EXPECTED) is not None, "saved vault shows the expected address")
tap("Done"); wait_for("Unlock vault", exact=True)
check(True, "home now offers Unlock (vault exists)")

# ---- unlock: wrong, then right
tap("Unlock vault"); tap_node(edit_fields()[0]); guard(); adb("shell", "input", "text", "wrong-passphrase-123"); tap("Unlock")
wait_for("Wrong passphrase.", exact=True, timeout=90); check(True, "wrong passphrase is rejected")
tap_node(edit_fields()[0]); guard(); adb("shell", "input", "text", PASS); tap("Unlock")
wait_for("Vault unlocked", exact=True, timeout=90)
check(find(EXPECTED) is not None, "correct passphrase unlocks and shows the expected address")

# ---- leaving the app locks the vault
adb("shell", "input", "keyevent", "KEYCODE_HOME"); time.sleep(2)
adb("shell", "am", "start", "-n", "app.isol8.vault/.MainActivity"); time.sleep(2)
wait_for("OFFLINE STATUS"); guard()
check(find("Vault unlocked", exact=True) is None and find("Unlock vault", exact=True) is not None, "leaving the app locked the vault")

# ---- delete (two taps)
if find("Development override: ignore offline checks"): tap("Development override: ignore offline checks")
tap("Delete vault from this device"); tap("Delete vault")
wait_for("Tap again to delete permanently", exact=True)
check(find("Vault deleted") is None, "first tap only arms the delete")
tap("Tap again to delete permanently")
wait_for("Vault deleted", exact=True); tap("OK")
wait_for("OFFLINE STATUS")
check(find("Create a new vault", exact=True) is not None, "after deleting, home offers create/restore again")

if find("Development override is on (tap to turn off)"): tap("Development override is on (tap to turn off)")
# uiautomator is privileged (shell-level test framework), so this says nothing about whether ordinary
# accessibility apps are blocked by setAccessibilityDataSensitive. Informational only.
print("\nRecovery words readable by uiautomator:", "no" if hidden_words else "yes (expected: it is privileged)")
print("Review screen buttons as uiautomator saw them:", [t or "<hidden>" for t in review][:4], "...")
