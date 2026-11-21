package app.isol8.vault

import android.content.Context
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.os.Build
import android.provider.Settings
import android.telephony.TelephonyManager

/**
 * Device-state checks the vault runs before creating, restoring or unlocking (docs/SECURITY.md, "The vault phone, in layers").
 * They read only what Android exposes without permissions. They catch mistakes; they can't prove the
 * device is offline, because a compromised OS could lie. Keeping the phone offline is the real protection.
 */
object OfflineChecks {
    /** ok = true (passes), false (fails, blocks the vault), null (couldn't check; shown as a warning). */
    data class Check(val label: String, val ok: Boolean?, val fix: String)

    fun run(context: Context): List<Check> {
        val cr = context.contentResolver
        fun global(name: String): Int? = try {
            Settings.Global.getInt(cr, name)
        } catch (e: Settings.SettingNotFoundException) {
            null
        } catch (e: SecurityException) {
            null
        }

        val checks = mutableListOf<Check>()
        checks += Check("Airplane mode on", global(Settings.Global.AIRPLANE_MODE_ON)?.let { it == 1 }, "turn on airplane mode")
        // wifi_on: 0 off, 1 on, 2 on despite airplane mode, 3 off because of airplane mode.
        checks += Check("Wi-Fi off", global(Settings.Global.WIFI_ON)?.let { it == 0 || it == 3 }, "turn off Wi-Fi")
        // bluetooth_on: 0 off, 1 on, 2 on despite airplane mode.
        checks += Check("Bluetooth off", global(Settings.Global.BLUETOOTH_ON)?.let { it == 0 }, "turn off Bluetooth")
        checks += Check("NFC off", nfcOff(context), "turn off NFC")
        val sim = simSlots(context)
        checks += Check("No SIM card", sim?.let { slots -> slots.all { it == TelephonyManager.SIM_STATE_ABSENT || it == TelephonyManager.SIM_STATE_NOT_READY } },
            "remove the SIM card and any eSIM" + (sim?.takeIf { it.isNotEmpty() }?.let { slots -> " (" + slots.mapIndexed { i, st -> "slot ${i + 1}: ${simStateName(st)}" }.joinToString(", ") + ")" } ?: ""))
        checks += Check("USB debugging off", global(Settings.Global.ADB_ENABLED)?.let { it == 0 }, "turn off USB debugging in Developer options")
        checks += Check("Wireless debugging off", global("adb_wifi_enabled")?.let { it == 0 } ?: true, "turn off Wireless debugging in Developer options")
        return checks
    }

    private fun nfcOff(context: Context): Boolean? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC)) return true
        return try {
            NfcAdapter.getDefaultAdapter(context)?.isEnabled?.not() ?: true
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Each SIM slot's state; empty without telephony hardware, null if it can't be read. A slot is clear when it's
     * ABSENT (an empty tray) or NOT_READY (how Android reports an eSIM chip with no profile, or a card with
     * nothing usable on it; checked on a Pixel 8 Pro). A SIM that can connect is READY or locked, and fails.
     */
    private fun simSlots(context: Context): List<Int>? {
        if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY)) return emptyList()
        return try {
            val tm = context.getSystemService(TelephonyManager::class.java) ?: return null
            val slots = if (Build.VERSION.SDK_INT >= 30) {
                tm.activeModemCount
            } else {
                @Suppress("DEPRECATION")
                tm.phoneCount
            }
            (0 until maxOf(slots, 1)).map { tm.getSimState(it) }
        } catch (e: Exception) {
            null
        }
    }

    private fun simStateName(state: Int): String = when (state) {
        TelephonyManager.SIM_STATE_ABSENT -> "empty"
        TelephonyManager.SIM_STATE_NOT_READY -> "no usable SIM"
        TelephonyManager.SIM_STATE_READY -> "SIM ready"
        TelephonyManager.SIM_STATE_PIN_REQUIRED, TelephonyManager.SIM_STATE_PUK_REQUIRED, TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "SIM locked"
        TelephonyManager.SIM_STATE_PERM_DISABLED -> "SIM disabled"
        TelephonyManager.SIM_STATE_CARD_IO_ERROR -> "SIM error"
        TelephonyManager.SIM_STATE_CARD_RESTRICTED -> "SIM restricted"
        else -> "unknown"
    }
}
