# Sets up a TEST device for hands-on testing: restores the public test phrase and saves it with a test
# passphrase, leaving the app on Home with the development override on. Delete the vault afterwards.
# Usage: python3 -I restore_for_manual_test.py <adb> <serial>
# Needs: the vault app open on Home, a screen lock set, no vault yet, and the screen kept awake.
import os
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "drive.py")).read())
PHRASE = ["abandon"] * 11 + ["about"]          # public BIP39 test phrase
EXPECTED = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
PASS = "isol8-e2e-test-pass"

def buttons(): return [n for n in nodes() if n["cls"].endswith("Button")]
def tap_node(n):
    x1, y1, x2, y2 = n["b"]; guard(); adb("shell", "input", "tap", str((x1+x2)//2), str((y1+y2)//2)); time.sleep(0.4)
def edit_fields(): return [n for n in nodes() if n["cls"].endswith("EditText")]

wait_for("OFFLINE STATUS"); guard()
if find("Development override: ignore offline checks"):
    tap("Development override: ignore offline checks"); time.sleep(1.5)  # let Home redraw before the next tap
check(find("Restore from a recovery phrase") is not None, "home offers restore (screen lock set, no vault yet, override on)")
tap("Restore from a recovery phrase"); tap("12 words")
for i, word in enumerate(PHRASE):
    wait_for(f"Word {i+1} of 12", exact=True)
    for c in word[:4]: tap(c)
    match = [n for n in buttons() if n["text"] == word]
    tap_node(match[0] if match else buttons()[0])
wait_for("Check your words", exact=True); tap("Continue")
wait_for("Is this your wallet?", exact=True)
check(find(EXPECTED) is not None, f"address preview is {EXPECTED}")
tap("Yes, continue"); wait_for("Set a vault passphrase", exact=True)
tap_node(edit_fields()[0]); guard(); adb("shell", "input", "text", PASS)
tap_node(edit_fields()[1]); guard(); adb("shell", "input", "text", PASS)
tap("Restore vault"); wait_for("Vault restored", exact=True, timeout=90)
tap("Done"); wait_for("Pair with the isol8 dashboard", exact=True)
check(True, f"test vault saved (passphrase {PASS}); home offers pairing")
