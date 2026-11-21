package app.isol8.vault

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/**
 * What this phone can prove about itself, offline (docs/SECURITY.md, "Device tiers"): where the vault's key lives, whether the
 * bootloader is locked and verified boot passed, the OS and its patch level, and the tier that adds up to.
 *
 * Boot state comes from Android key attestation: a throwaway key is created in the Keystore, and the certificate the
 * secure hardware signs for it carries the root of trust (bootloader locked, verified boot state) and patch levels.
 * The key is deleted afterwards. It catches an unlocked bootloader or a software-only keystore; like every on-device
 * check, it can't prove a fully compromised phone honest.
 */
object DeviceReport {
    enum class Tier(val label: String) { BEST("Best"), GOOD("Good"), BUDGET("Budget"), MINIMUM("Minimum"), UNKNOWN("Unknown") }
    enum class Boot { VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED, UNKNOWN }

    data class Report(
        /** Where the vault's own key lives: "StrongBox", "TEE", "software", "no key" (no vault yet) or "unknown". */
        val keyStorage: String,
        val strongBoxAvailable: Boolean,
        /** null: couldn't be measured (no attestation on this device). */
        val bootloaderLocked: Boolean?,
        val boot: Boot,
        /** Security patch level as reported by the OS, "2026-11-05" style. */
        val patchLevel: String,
        val os: String,
        val grapheneOs: Boolean,
        val tier: Tier,
        /** Where the boot state came from: signed by the secure hardware, or only reported by the OS itself. */
        val bootFromAttestation: Boolean,
        /** A userdebug or eng build: easier to root than a user build. */
        val debugBuild: Boolean,
    )

    private const val ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"
    private const val ALIAS = "isol8-device-report"

    fun run(context: Context, keyStorage: String): Report {
        val strongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val attested = try { rootOfTrust() } catch (e: Exception) { null }
        // Without attestation (common on Samsungs once the bootloader was unlocked), fall back to what the OS reports.
        val root = attested ?: rootFromProperties()
        val graphene = isGrapheneOs(context)
        val os = when {
            graphene -> "GrapheneOS (Android ${Build.VERSION.RELEASE})"
            Build.PRODUCT.startsWith("lineage", ignoreCase = true) || Build.DISPLAY.contains("lineage", ignoreCase = true) -> "LineageOS (Android ${Build.VERSION.RELEASE})"
            else -> "Android ${Build.VERSION.RELEASE}"
        }
        val locked = root?.locked
        val boot = root?.boot ?: Boot.UNKNOWN
        val tier = when {
            locked == null -> Tier.UNKNOWN
            !locked || boot == Boot.UNVERIFIED || boot == Boot.FAILED -> Tier.BUDGET
            keyStorage == "software" -> Tier.MINIMUM
            keyStorage == "StrongBox" && graphene && boot == Boot.SELF_SIGNED -> Tier.BEST
            else -> Tier.GOOD
        }
        return Report(keyStorage, strongBox, locked, boot, Build.VERSION.SECURITY_PATCH, os, graphene, tier,
            bootFromAttestation = attested != null, debugBuild = Build.TYPE != "user")
    }

    /** GrapheneOS ships its own app store; together with a locked, self-signed boot that identifies it well enough. */
    private fun isGrapheneOs(context: Context): Boolean = try {
        context.packageManager.getPackageInfo("app.grapheneos.apps", 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    private class Root(val locked: Boolean, val boot: Boot)

    /** The bootloader's own report (green, yellow, orange, red), as the OS passes it on. Not signed by hardware. */
    private fun rootFromProperties(): Root? {
        val state = prop("ro.boot.verifiedbootstate").lowercase()
        val device = prop("ro.boot.vbmeta.device_state").lowercase()
        val boot = when (state) {
            "green" -> Boot.VERIFIED
            "yellow" -> Boot.SELF_SIGNED
            "orange" -> Boot.UNVERIFIED
            "red" -> Boot.FAILED
            else -> return null
        }
        val locked = when (device) {
            "locked" -> true
            "unlocked" -> false
            else -> state != "orange"
        }
        return Root(locked, boot)
    }

    /** One system property, through the getprop tool (no hidden APIs). Empty if unreadable. */
    private fun prop(name: String): String = try {
        val p = ProcessBuilder("getprop", name).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().use { it.readText() }.trim()
        p.waitFor()
        out
    } catch (e: Exception) {
        ""
    }

    private fun rootOfTrust(): Root? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        try {
            val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .build(),
                )
                generateKeyPair()
            }
            val leaf = ks.getCertificateChain(ALIAS)?.firstOrNull() as? X509Certificate ?: return null
            val ext = leaf.getExtensionValue(ATTESTATION_OID) ?: return null
            val description = Der.read(Der.read(ext).value) // the extension value is an OCTET STRING around it
            val fields = description.children()
            if (fields.size < 8) return null
            if (!fields[4].value.contentEquals(challenge)) return null // not the certificate we just asked for
            // Hardware-enforced first, then software-enforced (a software-only keystore puts it there).
            val root = (fields[7].children() + fields[6].children()).firstOrNull { it.tag == 704 } ?: return null
            val parts = Der.read(root.value).children()
            if (parts.size < 3) return null
            val locked = parts[1].value.firstOrNull()?.toInt() != 0
            val boot = when (parts[2].value.lastOrNull()?.toInt()) {
                0 -> Boot.VERIFIED
                1 -> Boot.SELF_SIGNED
                2 -> Boot.UNVERIFIED
                3 -> Boot.FAILED
                else -> Boot.UNKNOWN
            }
            return Root(locked, boot)
        } finally {
            try { ks.deleteEntry(ALIAS) } catch (e: Exception) { /* nothing to clean up */ }
        }
    }

    /** Just enough DER to read an attestation record: tag (including multi-byte context tags), length, value. */
    private object Der {
        class Element(val tag: Int, val constructed: Boolean, val value: ByteArray) {
            fun children(): List<Element> {
                val out = mutableListOf<Element>()
                var i = 0
                while (i < value.size) {
                    val (e, used) = parse(value, i)
                    out += e
                    i += used
                }
                return out
            }
        }

        fun read(bytes: ByteArray): Element = parse(bytes, 0).first

        private fun parse(b: ByteArray, start: Int): Pair<Element, Int> {
            var i = start
            val first = b[i++].toInt() and 0xFF
            val constructed = first and 0x20 != 0
            var tag = first and 0x1F
            if (tag == 0x1F) { // high tag number: base-128, high bit means "more"
                tag = 0
                do {
                    val t = b[i++].toInt() and 0xFF
                    tag = (tag shl 7) or (t and 0x7F)
                } while (t and 0x80 != 0)
            }
            var len = b[i++].toInt() and 0xFF
            if (len and 0x80 != 0) {
                val n = len and 0x7F
                require(n in 1..4) { "bad DER length" }
                len = 0
                repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xFF) }
            }
            require(len >= 0 && i + len <= b.size) { "DER runs past its end" }
            return Element(tag, constructed, b.copyOfRange(i, i + len)) to (i + len - start)
        }
    }
}
