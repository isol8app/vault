package app.isol8.vault

import android.Manifest
import android.app.Activity
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.window.OnBackInvokedDispatcher
import app.isol8.vault.core.Acceptance
import app.isol8.vault.core.AddressBookEntry
import app.isol8.vault.core.Action
import app.isol8.vault.core.Amounts
import app.isol8.vault.core.Base45
import app.isol8.vault.core.Base58
import app.isol8.vault.core.Bip39
import app.isol8.vault.core.Decision
import app.isol8.vault.core.Ed25519Signer
import app.isol8.vault.core.Frames
import app.isol8.vault.core.InvalidMnemonicException
import app.isol8.vault.core.Pairing
import app.isol8.vault.core.PassphraseAttempts
import app.isol8.vault.core.Payload
import app.isol8.vault.core.ProtocolException
import app.isol8.vault.core.TxSigning
import app.isol8.vault.core.VaultSettings
import app.isol8.vault.core.Warning
import app.isol8.vault.core.sha256
import app.isol8.vault.core.utf8
import app.isol8.vault.crypto.SolanaKeys
import app.isol8.vault.crypto.VaultEnvelope
import app.isol8.vault.crypto.VaultEnvelopeException
import app.isol8.vault.crypto.VaultSecret
import app.isol8.vault.qr.QrCodes
import java.security.SecureRandom

/**
 * The vault app: one activity, screens built from plain views.
 * Secrets live only in [secrets] while a flow runs; leaving the app (or the screen turning off) wipes them
 * and returns to Home, which also locks an unlocked vault.
 */
class MainActivity : Activity() {
    private lateinit var ui: Ui
    private lateinit var container: LinearLayout
    private lateinit var scroll: ScrollView
    private lateinit var store: VaultStore
    /** Address book and fee-warning setting, under the vault's Keystore key (see [VaultSettings]). */
    private lateinit var settingsStore: VaultStore
    /** Wrong passphrases and the wait they've earned (see [mustWait]). */
    private lateinit var attemptsStore: VaultStore
    private val rng = SecureRandom()

    private var onHome = true
    private var busy = false
    /** Between onStart and onStop: work that finishes while the app is in the background must not leave it unlocked. */
    private var started = false
    /** Debug builds only: lets development continue on a networked test device. Off at every launch. */
    private var devOverride = false

    /** Everything secret held by the current flow. */
    private class Secrets {
        var entropy: ByteArray? = null
        var words: List<String>? = null
        var restore: MutableList<String>? = null
        var returnToReview = false
        /** Typing words for Check my backup, not for a restore. */
        var checking = false
        /** The unlocked key while the user reviews a transaction. BouncyCastle's copy can't be zeroed; dropped here. */
        var signer: Ed25519Signer? = null

        fun wipe() {
            signer = null
            entropy?.fill(0)
            entropy = null
            words = null
            restore?.fill("")
            restore = null
            returnToReview = false
            checking = false
        }
    }

    private val secrets = Secrets()

    /** The live camera while a scan screen is showing. Every screen change stops it. */
    private var camera: QrCamera? = null
    /** What to do once the user answers the camera permission prompt. */
    private var afterCameraPermission: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording or recent-apps thumbnails.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        ui = Ui(this)
        store = VaultStore(this)
        settingsStore = VaultStore(this, fileName = "settings.bin", purpose = "settings")
        attemptsStore = VaultStore(this, fileName = "attempts.bin", purpose = "attempts")
        container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = ui.dp(20)
            setPadding(pad, pad, pad, ui.dp(32))
        }
        scroll = ScrollView(this).apply {
            setBackgroundColor(Palette.BG)
            addView(container)
        }
        window.decorView.setBackgroundColor(Palette.BG)
        scroll.setOnApplyWindowInsetsListener { v, insets ->
            val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
        setContentView(scroll)
        if (Build.VERSION.SDK_INT >= 33) {
            onBackInvokedDispatcher.registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT) { goBack() }
        }
        showHome()
    }

    @Deprecated("Used below Android 13 only; newer versions use the OnBackInvokedDispatcher callback.")
    override fun onBackPressed() = goBack()

    private fun goBack() {
        if (busy) return
        if (onHome) finish() else showHome()
    }

    override fun onResume() {
        super.onResume()
        if (onHome) showHome() // refresh the offline status after a trip to Settings
    }

    override fun onStart() {
        super.onStart()
        started = true
    }

    override fun onStop() {
        super.onStop()
        started = false
        // Leaving the app or turning off the screen wipes secrets and locks the vault. Work still running (an unlock,
        // say) ends at Home instead: see [working].
        if (!busy) showHome()
    }

    override fun onDestroy() {
        camera?.stop()
        secrets.wipe()
        super.onDestroy()
    }

    // ---------------------------------------------------------------- navigation helpers

    private fun show(views: List<View?>, home: Boolean = false) {
        onHome = home
        camera?.stop()
        camera = null
        setFullBrightness(false)
        container.removeAllViews()
        views.filterNotNull().forEach(container::addView)
        scroll.scrollTo(0, 0)
    }

    private fun isDebuggable() = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    private fun offline() = OfflineChecks.run(this).none { it.ok == false }

    /** True if vault actions are allowed now; otherwise returns to Home, which explains why. */
    private fun gate(): Boolean {
        if (offline() || (isDebuggable() && devOverride)) return true
        showHome()
        return false
    }

    private fun <T> working(message: String, task: () -> T, onDone: (Result<T>) -> Unit) {
        busy = true
        show(listOf(ui.title(message), ProgressBar(this)))
        Thread {
            val result = runCatching(task)
            runOnUiThread {
                busy = false
                // Finished while the app was in the background: drop the result (an unlocked key, say) and lock.
                if (!isDestroyed) if (started) onDone(result) else showHome()
            }
        }.start()
    }

    // ---------------------------------------------------------------- home

    private fun showHome() {
        secrets.wipe()
        val checks = OfflineChecks.run(this)
        val isOffline = checks.none { it.ok == false }
        val allowed = isOffline || (isDebuggable() && devOverride)
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = android.view.Gravity.CENTER_VERTICAL
            addView(ui.title("isol8 vault"), LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(ui.pill(if (isOffline) "✓ Offline" else "✕ Online", isOffline))
        }
        val views = mutableListOf<View?>(header)
        if (isDebuggable()) views += ui.warning("Development build: test keys only, never real funds.")

        if (!isOffline) {
            // What to fix first, then what's already fine.
            views += ui.body("The vault only works while this phone is fully offline. To fix:")
            views += ui.card(
                checks.sortedBy { if (it.ok == false) 0 else if (it.ok == null) 1 else 2 }.map { c ->
                    ui.check(c.ok, c.label, if (c.ok == false) c.fix.replaceFirstChar(Char::uppercase) + "." else if (c.ok == null) "Couldn't check: make sure it's off." else null)
                },
            )
            if (isDebuggable()) {
                views += ui.dangerButton(if (devOverride) "Development override is on (tap to turn off)" else "Development override: ignore offline checks") {
                    devOverride = !devOverride
                    showHome()
                }
                if (devOverride) views += ui.note("Offline checks are being ignored. Test keys only. Release builds have no override.")
            }
        } else {
            views += ui.card(ui.check(true, "All offline checks pass", "Airplane mode on, radios off, no SIM, no debugging."))
        }

        when {
            !store.isDeviceSecure() -> views += ui.error("Set a screen lock (PIN, pattern or password) in Android settings first. The vault's storage key requires one.")
            !allowed -> views += ui.note("Vault actions are disabled until this phone is offline.")
            store.exists() -> {
                views += ui.card(
                    ui.text("Vault ready", 20f, bold = true),
                    ui.note("Your address shows after you unlock: a locked phone doesn't reveal what it guards."),
                )
                views += ui.primaryButton("Sign a transaction") { showSignUnlock() }
                views += ui.button("Pair with the isol8 dashboard") { showPairScan() }
                views += ui.button("Address book") { showAddressBook(null) }
                views += ui.button("Unlock: address and settings") { showUnlock() }
                views += ui.button("Check my backup") { showCheckIntro() }
            }
            else -> {
                views += ui.primaryButton("Create a new vault") { showCreateIntro() }
                views += ui.button("Restore from a recovery phrase") { showRestoreLength() }
            }
        }
        views += deviceRow()
        views += ui.button("Diagnostics") { showDiagnostics() }
        if (allowed && store.exists() && store.isDeviceSecure()) {
            views += ui.dangerButton("Delete vault from this device") { showDelete(armed = false) }
        }
        views += ui.note("This app cannot connect to the internet. The only official site is isol8.app.").apply {
            gravity = android.view.Gravity.CENTER
            setPadding(0, ui.dp(20), 0, 0)
        }
        show(views, home = true)
    }

    // ---------------------------------------------------------------- device report

    private fun keyStorage(): String = try {
        if (store.exists()) store.keySecurityLevel() else "no key"
    } catch (e: Exception) {
        "unknown"
    }

    /** A one-line summary on Home that opens the full report. */
    private fun deviceRow(): View {
        val r = DeviceReport.run(this, keyStorage())
        val good = r.tier == DeviceReport.Tier.BEST || r.tier == DeviceReport.Tier.GOOD
        return ui.button("Device: ${r.tier.label} tier  ›") { showDeviceReport() }.apply {
            setTextColor(if (good) Palette.GOOD_TEXT else if (r.tier == DeviceReport.Tier.UNKNOWN) Palette.TEXT else Palette.BAD_TEXT)
        }
    }

    /** A security patch level ("2024-09-05") older than a year. False when it can't be read. */
    private fun patchIsOld(level: String): Boolean = try {
        java.time.LocalDate.parse(level).isBefore(java.time.LocalDate.now().minusYears(1))
    } catch (e: Exception) {
        false
    }

    private fun showDeviceReport() {
        val r = DeviceReport.run(this, keyStorage())
        val views = mutableListOf<View?>(ui.title("Device report"))
        val (summary, kind) = when (r.tier) {
            DeviceReport.Tier.BEST -> "Best tier. A Pixel running GrapheneOS, with the vault's key in the secure element: close to a hardware wallet, with a bigger screen." to 0
            DeviceReport.Tier.GOOD -> "Good tier. A locked bootloader and hardware-backed keys." +
                (if (r.keyStorage == "StrongBox" && !r.grapheneOs) " For Best, GrapheneOS on a Pixel adds hardening throughout the OS." else " For Best, use a Pixel with GrapheneOS, whose key lives in a secure element.") to 0
            DeviceReport.Tier.BUDGET -> "Budget tier. The bootloader is unlocked or verified boot is off, so someone with this phone in hand could replace the system under the app. Fine for small amounts; see isol8.app for the recommended setups." to 2
            DeviceReport.Tier.MINIMUM -> "Minimum tier. The vault's key is held in software, not in secure hardware. Use a phone with a hardware-backed keystore for anything more than small amounts." to 2
            DeviceReport.Tier.UNKNOWN -> "This phone doesn't support key attestation and doesn't report its boot state, so the vault can't measure it." to 1
        }
        views += when (kind) {
            0 -> ui.good(summary)
            1 -> ui.warning(summary)
            else -> ui.error(summary)
        }
        val keyText = when (r.keyStorage) {
            "StrongBox" -> "Secure element (StrongBox): the vault key can't be copied off the chip."
            "TEE" -> "Trusted execution environment: hardware-backed, but not a separate secure chip." + if (r.strongBoxAvailable) " This phone has StrongBox, but the key was made without it." else ""
            "software" -> "Software only: no hardware protection for the vault key."
            "no key" -> if (r.strongBoxAvailable) "No vault yet. This phone has a secure element, which the vault will use." else "No vault yet. This phone has no secure element; the vault will use the trusted execution environment."
            else -> "Couldn't read where the key lives."
        }
        val keyOk = when (r.keyStorage) { "StrongBox" -> true; "software" -> false; "TEE" -> true; "no key" -> null; else -> null }
        val bootText = when {
            r.bootloaderLocked == null -> "Couldn't be measured on this phone."
            !r.bootloaderLocked -> "Unlocked: the system can be replaced. A vault phone should have a locked bootloader."
            r.boot == DeviceReport.Boot.VERIFIED -> "Locked. Verified boot passed with the manufacturer's key."
            r.boot == DeviceReport.Boot.SELF_SIGNED -> "Locked. Verified boot passed with the OS's own key" + if (r.grapheneOs) " (GrapheneOS)." else "."
            else -> "Locked, but verified boot didn't pass."
        }
        val bootOk = r.bootloaderLocked?.let { it && (r.boot == DeviceReport.Boot.VERIFIED || r.boot == DeviceReport.Boot.SELF_SIGNED) }
        val bootSource = if (r.bootloaderLocked != null && !r.bootFromAttestation)
            " Reported by the system itself: this phone doesn't support key attestation, so it isn't hardware-signed." else ""
        val networkPermissions = requestedPermissions().filter { it in NETWORK_PERMISSIONS }
        val noNetwork = networkPermissions.isEmpty()
        views += ui.card(
            ui.check(keyOk, "Key storage", keyText),
            ui.divider(),
            ui.check(bootOk, "Bootloader", bootText + bootSource),
            ui.divider(),
            ui.check(
                if (patchIsOld(r.patchLevel) || r.debugBuild) null else true, r.os,
                (if (patchIsOld(r.patchLevel)) "Security patch: ${r.patchLevel}, more than a year old. Offline it matters less, but update it before the phone holds the vault."
                else "Security patch: ${r.patchLevel}.") +
                    if (r.debugBuild) " This is a debug (userdebug) build of the OS, which is easier to root than a normal one." else "",
            ),
            ui.divider(),
            ui.check(noNetwork, "No network permission", if (noNetwork) "This app can't open a connection, and Android enforces it."
                else "This app requests ${networkPermissions.joinToString { it.substringAfterLast('.') }}. A real vault never does: don't trust this copy."),
            ui.divider(),
            ui.check(offline(), "Offline checks", if (offline()) "Airplane mode, radios off, no SIM, no debugging." else "Not all pass: see Home."),
        )
        views += ui.note("Measured on this phone, offline, with Android's key attestation. It catches an unlocked bootloader or a software-only keystore. Like any on-device check, it can't prove a fully compromised phone honest.")
        views += ui.button("Back") { showHome() }
        show(views)
    }

    // ---------------------------------------------------------------- create

    /** 24 words by default; 12 only after the one screen that explains the choice */
    private fun showCreateIntro(wordCount: Int = 24): Unit = show(
        listOf(
            ui.title("Create a new vault"),
            ui.body("You'll get $wordCount words: your recovery phrase. Write them on paper, in order."),
            ui.body("Anyone with these words controls everything in the vault. They're also the only way to recover it if this device is lost or reset."),
            ui.error("Never photograph them, type them into another device, or store them online."),
            ui.button("Show my $wordCount words") {
                if (!gate()) return@button
                // 12 words: 128 bits of entropy; 24 words: 256 (BIP39).
                val entropy = ByteArray(if (wordCount == 12) 16 else 32).also(rng::nextBytes)
                secrets.entropy = entropy
                secrets.words = Bip39.entropyToMnemonic(entropy)
                showWords()
            },
            if (wordCount == 24) ui.textButton("Use 12 words instead") { showWordCountChoice() }
            else ui.textButton("Use 24 words (recommended)") { showCreateIntro(24) },
            ui.button("Cancel") { showHome() },
        ),
    )

    private fun showWordCountChoice(): Unit = show(
        listOf(
            ui.title("12 or 24 words?"),
            ui.body("12 words are secure today and easier to write down. 24 words keep a bigger safety margin for the future, including a possible post-quantum Solana."),
            ui.body("isol8 recommends 24."),
            ui.primaryButton("Keep 24 words") { showCreateIntro(24) },
            ui.button("Use 12 words") { showCreateIntro(12) },
        ),
    )

    private fun showWords() {
        val words = secrets.words ?: return showHome()
        show(
            listOf(
                ui.title("Your recovery phrase"),
                ui.body("Write all ${words.size} words on paper, in this order."),
                ui.grid(2, words.mapIndexed { i, w -> ui.sensitive(ui.text("${i + 1}. $w", 19f)) }),
                ui.button("I've written them down") { startConfirm() },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun startConfirm() {
        val words = secrets.words ?: return showHome()
        val positions = words.indices.shuffled(rng).take(3).sorted()
        confirmStep(positions, 0)
    }

    private fun confirmStep(positions: List<Int>, step: Int) {
        val words = secrets.words ?: return showHome()
        val pos = positions[step]
        val correct = words[pos]
        val options = (Bip39.WORDS.filter { it !in words }.shuffled(rng).take(5) + correct).shuffled(rng)
        show(
            listOf(
                ui.title("Check your backup"),
                ui.body("Which is word #${pos + 1}? (${step + 1} of 3)"),
                ui.grid(2, options.map { w ->
                    ui.sensitive(
                        ui.button(w) {
                            when {
                                w != correct -> showConfirmFailed(pos)
                                step == positions.lastIndex -> showSetPassphrase(restored = false)
                                else -> confirmStep(positions, step + 1)
                            }
                        },
                    )
                }),
                ui.button("Show my words again") { showWords() },
            ),
        )
    }

    private fun showConfirmFailed(pos: Int): Unit = show(
        listOf(
            ui.title("That's not word #${pos + 1}"),
            ui.body("Check what you wrote down, then try again. Your backup has to be exactly right."),
            ui.button("Show my words again") { showWords() },
        ),
    )

    // ---------------------------------------------------------------- restore

    private fun showRestoreLength(): Unit = show(
        listOf(
            ui.title(if (secrets.checking) "Check my backup" else "Restore from a recovery phrase"),
            ui.body(if (secrets.checking) "How many words are on your paper?" else "How many words does your phrase have?"),
            ui.grid(3, listOf(12, 15, 18, 21, 24).map { n ->
                ui.button("$n words") {
                    if (!gate()) return@button
                    secrets.restore = MutableList(n) { "" }
                    showWordEntry(0, "")
                }
            }),
            ui.note("Words are entered with this screen's own keyboard, never the system keyboard."),
            ui.note("Phrases that use a BIP39 passphrase (\"25th word\") aren't supported yet."),
            ui.button("Cancel") { showHome() },
        ),
    )

    private fun showWordEntry(index: Int, prefix: String) {
        val list = secrets.restore ?: return showHome()
        val candidates = Bip39.wordsStartingWith(prefix)
        val views = mutableListOf<View?>(
            ui.title("Word ${index + 1} of ${list.size}"),
            ui.sensitive(ui.text(if (prefix.isEmpty()) "Tap the first letters" else prefix, 24f, bold = prefix.isNotEmpty())),
        )
        if (prefix.isNotEmpty() && candidates.size <= 12) {
            views += ui.grid(3, candidates.map { w ->
                ui.sensitive(ui.button(w) {
                    list[index] = w
                    if (secrets.returnToReview || index == list.lastIndex) showReview() else showWordEntry(index + 1, "")
                })
            })
        } else if (prefix.isNotEmpty()) {
            views += ui.note("${candidates.size} words start with \"$prefix\". Keep going.")
        }
        val letters = ('a'..'z').map { c ->
            val next = prefix + c
            ui.key(c.toString(), enabled = Bip39.WORDS.any { it.startsWith(next) }) { showWordEntry(index, next) }
        }
        views += ui.grid(7, letters)
        views += ui.grid(
            2,
            listOf(
                ui.key("⌫ Delete", enabled = prefix.isNotEmpty()) { showWordEntry(index, prefix.dropLast(1)) },
                ui.key(if (index > 0 && !secrets.returnToReview) "Previous word" else "Cancel") {
                    if (index > 0 && !secrets.returnToReview) showWordEntry(index - 1, "") else if (secrets.returnToReview) showReview() else showHome()
                },
            ),
        )
        show(views)
    }

    private fun showReview(error: String? = null) {
        val list = secrets.restore ?: return showHome()
        secrets.returnToReview = false
        show(
            listOf(
                ui.title("Check your words"),
                error?.let { ui.error(it) },
                ui.body("Compare them with your paper, in order. To fix a word, tap it."),
                ui.button(if (secrets.checking) "Check against this vault" else "Continue") {
                    try {
                        val entropy = Bip39.mnemonicToEntropy(list)
                        secrets.entropy = entropy
                        secrets.words = list.toList()
                        if (secrets.checking) showCheckUnlock()
                        else showRestorePreview(Base58.encode(SolanaKeys.signer(list).publicKey))
                    } catch (e: InvalidMnemonicException) {
                        showReview(
                            if (secrets.checking) "These words aren't a valid recovery phrase: one is wrong, missing or out of order. Check them against your paper."
                            else e.message,
                        )
                    }
                },
                ui.grid(3, list.mapIndexed { i, w ->
                    ui.sensitive(ui.button("${i + 1}. $w") {
                        secrets.returnToReview = true
                        showWordEntry(i, "")
                    })
                }),
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun showRestorePreview(address: String): Unit = show(
        listOf(
            ui.title("Is this your wallet?"),
            ui.body("This phrase controls this Solana address (account 1):"),
            ui.mono(address),
            ui.note("Compare it with the address you expect. If it's different, a word may be wrong, or your old wallet used a BIP39 passphrase or a different derivation path."),
            ui.button("Yes, continue") { showSetPassphrase(restored = true) },
            ui.button("Back to my words") { showReview() },
        ),
    )

    // ---------------------------------------------------------------- passphrase and save

    private fun showSetPassphrase(restored: Boolean, error: String? = null) {
        val first = ui.passwordField("Vault passphrase")
        val second = ui.passwordField("Same passphrase again")
        show(
            listOf(
                ui.title("Set a vault passphrase"),
                ui.body("It unlocks the vault on this device. At least ${VaultEnvelope.MIN_PASSPHRASE_LENGTH} characters."),
                ui.note("It isn't part of your recovery phrase. If you forget it, delete the vault and restore from your words."),
                error?.let { ui.error(it) },
                first,
                second,
                ui.button(if (restored) "Restore vault" else "Create vault") {
                    val a = first.text.toString()
                    val b = second.text.toString()
                    first.text.clear()
                    second.text.clear()
                    when {
                        a.codePointCount(0, a.length) < VaultEnvelope.MIN_PASSPHRASE_LENGTH ->
                            showSetPassphrase(restored, "Use at least ${VaultEnvelope.MIN_PASSPHRASE_LENGTH} characters.")
                        a != b -> showSetPassphrase(restored, "The two passphrases don't match.")
                        else -> saveVault(a, restored)
                    }
                },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun saveVault(passphrase: String, restored: Boolean) {
        if (!gate()) return
        val entropy = secrets.entropy ?: return showHome()
        val words = secrets.words ?: return showHome()
        working("Encrypting your vault. This takes a few seconds.", {
            store.save(VaultEnvelope.seal(VaultSecret(entropy.copyOf()), passphrase))
            Base58.encode(SolanaKeys.signer(words).publicKey)
        }) { result ->
            secrets.wipe()
            result.fold(
                onSuccess = { address ->
                    show(
                        listOf(
                            ui.title(if (restored) "Vault restored" else "Vault created"),
                            ui.body("Your vault is stored on this device, encrypted with your passphrase and this device's secure hardware."),
                            ui.heading("Solana address (account 1)"),
                            ui.mono(address),
                            ui.note("Before sending anything here, check this address on this device."),
                            ui.button("Done") { showHome() },
                        ),
                    )
                },
                onFailure = { e -> showMessage("Couldn't save the vault", e.message ?: e.javaClass.simpleName) },
            )
        }
    }

    // ---------------------------------------------------------------- Check my backup

    private fun showCheckIntro(): Unit = show(
        listOf(
            ui.title("Check my backup"),
            ui.body("Type the words from your paper. The vault tells you whether they match it: it never shows its own words, and never says which word is wrong."),
            ui.note("You'll need your passphrase at the end."),
            ui.button("Start") {
                if (!gate()) return@button
                secrets.checking = true
                showRestoreLength()
            },
            ui.button("Cancel") { showHome() },
        ),
    )

    private fun showCheckUnlock(error: String? = null) {
        if (mustWait { showCheckUnlock() }) return
        val typed = secrets.entropy ?: return showHome()
        val field = ui.passwordField("Vault passphrase")
        show(
            listOf(
                ui.title("Check my backup"),
                ui.body("Enter your passphrase to compare these words with the vault."),
                error?.let { ui.error(it) },
                field,
                ui.button("Compare") {
                    val passphrase = field.text.toString()
                    field.text.clear()
                    if (!gate()) return@button
                    working("Comparing. This takes a few seconds.", {
                        val secret = openVault(passphrase)
                        try {
                            java.security.MessageDigest.isEqual(secret.entropy, typed)
                        } finally {
                            secret.wipe()
                        }
                    }) { result ->
                        result.fold(
                            onSuccess = { match ->
                                if (match) showMessage("Your backup matches", "The words on your paper are this vault's recovery phrase, in the right order.")
                                else showMessage("Your backup doesn't match", "These words aren't this vault's recovery phrase. Check each word and its position against your paper and try again. If your paper is wrong and the vault isn't backed up any other way, move the funds to a new vault you back up carefully.")
                            },
                            onFailure = { e ->
                                when {
                                    e is VaultEnvelopeException && e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED ->
                                        showCheckUnlock("Wrong passphrase.")
                                    else -> showMessage("Couldn't unlock", e.message ?: e.javaClass.simpleName)
                                }
                            },
                        )
                    }
                },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    // ---------------------------------------------------------------- unlock

    private fun showUnlock(error: String? = null) {
        if (mustWait { showUnlock() }) return
        val field = ui.passwordField("Vault passphrase")
        show(
            listOf(
                ui.title("Unlock vault"),
                error?.let { ui.error(it) },
                field,
                ui.button("Unlock") {
                    val passphrase = field.text.toString()
                    field.text.clear()
                    if (!gate()) return@button
                    working("Unlocking. This takes a few seconds.", {
                        val secret = openVault(passphrase)
                        try {
                            Base58.encode(SolanaKeys.signer(Bip39.entropyToMnemonic(secret.entropy), secret.bip39Passphrase).publicKey)
                        } finally {
                            secret.wipe()
                        }
                    }) { result ->
                        result.fold(
                            onSuccess = { address -> showUnlocked(address) },
                            onFailure = { e ->
                                when {
                                    e is VaultEnvelopeException && e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED ->
                                        showUnlock("Wrong passphrase.")
                                    e is KeyPermanentlyInvalidatedException ->
                                        showMessage("This vault can't be opened", "This device's vault key is no longer valid, for example because the screen lock was removed. Delete the vault and restore from your recovery phrase.")
                                    else -> showUnlock(e.message ?: e.javaClass.simpleName)
                                }
                            },
                        )
                    }
                },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun showUnlocked(address: String): Unit = show(
        listOf(
            ui.title("Vault unlocked"),
            ui.heading("Solana address (account 1)"),
            ui.address(address),
            // The vault is the trusted side: its own code proves the dashboard's Receive address is the real one.
            QrView(this, listOf(QrCodes.encodeAddress(address))),
            ui.note("To receive, check this matches the address the dashboard shows: this one comes from your vault."),
            ui.heading("Settings"),
            ui.button("Address book") { showAddressBook(address) },
            ui.button("Fee warning") { showFeeSetting(address) },
            ui.note("To sign, lock and choose Sign a transaction on the home screen: it unlocks, then scans. Leaving the app locks the vault."),
            ui.button("Lock") { showHome() },
        ),
    )

    // ---------------------------------------------------------------- settings: address book and fee warning
    // Reached only from the unlocked vault, so changing them needs the passphrase.

    private fun loadSettings(): VaultSettings =
        if (settingsStore.exists()) VaultSettings.decode(settingsStore.load()) else VaultSettings()

    /** Loads settings for a settings screen, or explains the problem. */
    private fun settingsOrError(): VaultSettings? = try {
        loadSettings()
    } catch (e: Exception) {
        showMessage("Settings can't be read", "The address book file is damaged (${e.message}). Signing is blocked until it's fixed. Reset it under Diagnostics.")
        null
    }

    private fun saveSettings(settings: VaultSettings) = settingsStore.save(settings.encode())

    private fun ownAddresses(vaultAddress: String) = listOf(Base58.decode(vaultAddress))

    /**
     * The address book. [vaultAddress] null: read-only, from the home screen without the passphrase (the book holds only
     * public addresses and your names for them; changing it, which changes what the vault signs against, needs the
     * unlock). Either way each entry can be shown as a QR code for the dashboard's Scan on Send.
     */
    private fun showAddressBook(vaultAddress: String?, removeArmed: String? = null) {
        val settings = settingsOrError() ?: return
        val views = mutableListOf<View?>(
            ui.title("Address book"),
            ui.body("Saved addresses are shown by name when you review a transaction, and any address that only looks like one of them gets a warning."),
        )
        if (settings.addressBook.isEmpty()) views += ui.note("No saved addresses yet.")
        for (e in settings.addressBook) {
            views += ui.heading(e.label)
            views += ui.address(e.base58)
            views += ui.button("Show QR code") { showAddressQr(e, vaultAddress) }
            if (vaultAddress != null) {
                views += ui.button(if (removeArmed == e.base58) "Tap again to remove \"${e.label}\"" else "Remove") {
                    if (removeArmed != e.base58) return@button showAddressBook(vaultAddress, e.base58)
                    saveSettings(settings.withoutEntry(e.address))
                    showAddressBook(vaultAddress)
                }
            }
        }
        if (vaultAddress != null) {
            views += ui.button("Add an address") { showAddAddress(vaultAddress) }
            views += ui.button("Back") { showUnlocked(vaultAddress) }
        } else {
            views += ui.note("To add or remove addresses, choose Unlock: address and settings.")
            views += ui.button("Back") { showHome() }
        }
        show(views)
    }

    /** One entry's address as a QR code, for the dashboard's Scan on Send. Only the address is in the code: its name stays here. */
    private fun showAddressQr(entry: AddressBookEntry, vaultAddress: String?) {
        show(
            listOf(
                ui.title(entry.label),
                ui.address(entry.base58),
                QrView(this, listOf(QrCodes.encodeAddress(entry.base58))),
                ui.note("On the dashboard: Send, then Scan, and point it here. Only the address is in this code: its name stays on this vault, and shows again when you review the transaction."),
                ui.button("Back") { showAddressBook(vaultAddress) },
            ),
        )
        setFullBrightness(true)
    }

    private fun showAddAddress(vaultAddress: String, error: String? = null) {
        val field = ui.textField("Solana address")
        show(
            listOf(
                ui.title("Add an address"),
                ui.body("Scan the receive QR code of the wallet you'll send to, or type the address."),
                ui.button("Scan a QR code") { withCamera { showAddressScan(vaultAddress) } },
                ui.heading("Or type it"),
                error?.let { ui.error(it) },
                field,
                ui.button("Continue") {
                    val address = VaultSettings.parseAddress(field.text.toString())
                        ?: return@button showAddAddress(vaultAddress, "That isn't a Solana address. Check every character.")
                    showNameAddress(vaultAddress, address, typed = true)
                },
                ui.button("Cancel") { showAddressBook(vaultAddress) },
            ),
        )
    }

    private fun showAddressScan(vaultAddress: String) {
        val status = ui.body("Looking for a QR code…")
        val cam = QrCamera(
            this,
            onText = { text ->
                val address = VaultSettings.parseAddress(text)
                if (address == null) status.text = "That QR code isn't a Solana address." else showNameAddress(vaultAddress, address, typed = false)
            },
            onError = { message -> showMessage("Camera problem", message) },
            isol8Only = false,
        )
        show(
            listOf(
                ui.title("Scan an address"),
                ui.body("Point the camera at the wallet's receive QR code."),
                cam.view,
                status,
                ui.button("Cancel") { showAddAddress(vaultAddress) },
            ),
        )
        camera = cam
    }

    private fun showNameAddress(vaultAddress: String, address: ByteArray, typed: Boolean, error: String? = null) {
        val settings = settingsOrError() ?: return
        val name = ui.textField("Name, e.g. Desk wallet")
        val views = mutableListOf<View?>(
            ui.title("Name this address"),
            ui.address(Base58.encode(address)),
            ui.note(
                if (typed) "Compare every character with where you copied it from. A typo gives a different, valid address."
                else "Compare it with the address the other wallet shows.",
            ),
        )
        settings.lookalikeWarnings(address, ownAddresses(vaultAddress)).forEach { views += ui.error(it) }
        views += error?.let { ui.error(it) }
        views += name
        views += ui.button("Save") {
            val label = name.text.toString()
            val check = settings.checkNewEntry(label, address, ownAddresses(vaultAddress))
            if (check.error != null) return@button showNameAddress(vaultAddress, address, typed, check.error)
            saveSettings(settings.withEntry(label, address))
            showAddressBook(vaultAddress)
        }
        views += ui.button("Cancel") { showAddressBook(vaultAddress) }
        show(views)
    }

    private fun showFeeSetting(vaultAddress: String) {
        val settings = settingsOrError() ?: return
        val views = mutableListOf<View?>(
            ui.title("Fee warning"),
            ui.body("When a transaction could cost more than this in network fees, the review shows a red warning. A hacked dashboard could otherwise drain SOL through fees."),
        )
        for (t in VaultSettings.THRESHOLD_CHOICES) {
            val current = t == settings.highFeeThresholdLamports
            val default = t == Acceptance.DEFAULT_HIGH_FEE_THRESHOLD_LAMPORTS
            views += ui.button((if (current) "✓ " else "") + Amounts.sol(t.toString()) + if (default) " (default)" else "") {
                saveSettings(settings.withThreshold(t))
                showFeeSetting(vaultAddress)
            }
        }
        views += ui.button("Back") { showUnlocked(vaultAddress) }
        show(views)
    }

    // ---------------------------------------------------------------- QR scanning and display

    /** Asks for the camera permission if needed, then runs [then]. */
    private fun withCamera(then: () -> Unit) {
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) return then()
        afterCameraPermission = then
        requestPermissions(arrayOf(Manifest.permission.CAMERA), CAMERA_REQUEST)
    }

    @Deprecated("Framework Activity callback; this app uses no AndroidX.")
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != CAMERA_REQUEST) return
        val then = afterCameraPermission
        afterCameraPermission = null
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            then?.invoke()
        } else {
            showMessage(
                "Camera needed",
                "The vault reads requests from the dashboard as QR codes, so it needs the camera. Nothing is saved or sent. " +
                    "If Android stopped asking, allow it in Settings › Apps › isol8 vault › Permissions.",
            )
        }
    }

    /**
     * A scan screen. Collects the frames of one payload (any order, PROTOCOL.md §3.3), resetting after
     * 30 seconds without a new part, and calls [onPayload] with the reassembled bytes.
     */
    private fun showScan(title: String, instructions: String, onPayload: (ByteArray) -> Unit) {
        val reassembler = Frames.Reassembler()
        var lastPart = 0L
        val status = ui.body("Looking for a QR code…")
        val debugLine = if (isDebuggable()) ui.note("Debug: waiting for camera frames") else null
        val cam = QrCamera(
            this,
            onText = { text ->
                val now = android.os.SystemClock.elapsedRealtime()
                if (lastPart != 0L && now - lastPart > SCAN_RESET_MS) reassembler.reset()
                try {
                    when (val r = reassembler.add(text)) {
                        is Frames.ScanResult.Partial -> {
                            lastPart = now
                            status.text = "Got part ${r.have} of ${r.total}. Keep the camera on the code."
                        }
                        is Frames.ScanResult.Complete -> onPayload(r.payload)
                    }
                } catch (e: ProtocolException) {
                    reassembler.reset()
                    status.text = "That QR code isn't valid: ${e.message}"
                }
            },
            onError = { message -> showMessage("Camera problem", message) },
            onDebug = debugLine?.let { line -> { text: String -> line.text = text } },
        )
        show(listOf(ui.title(title), ui.body(instructions), cam.view, status, debugLine, ui.button("Cancel") { showHome() }))
        camera = cam
    }

    /** Shows payload [bytes] as one or more looping QR frames, at full screen brightness. */
    private fun showQr(title: String, intro: String, bytes: ByteArray, after: List<View?>) {
        val frames = Frames.encode(bytes).map(QrCodes::encode)
        val count = if (frames.size > 1) ui.note("${frames.size} codes, shown in turn.").apply { gravity = android.view.Gravity.CENTER } else null
        show(listOf(ui.title(title), ui.body(intro), QrView(this, frames), count) + after)
        setFullBrightness(true)
    }

    private fun setFullBrightness(on: Boolean) {
        val attrs = window.attributes
        attrs.screenBrightness = if (on) 1f else WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE
        window.attributes = attrs
    }

    // ---------------------------------------------------------------- pairing

    private fun showPairScan() {
        if (!gate()) return
        withCamera {
            if (!gate()) return@withCamera
            showScan(
                "Pair with the dashboard",
                "On isol8.app, choose Pair a vault, then point this camera at the QR code.",
            ) { bytes ->
                val payload = try {
                    Payload.decode(bytes)
                } catch (e: ProtocolException) {
                    return@showScan showMessage("Not a valid request", e.message ?: "The QR code couldn't be read.")
                }
                when (payload) {
                    is Payload.PairRequest ->
                        if (Pairing.checkOrigin(payload.origin, isDebuggable()) == Pairing.OriginCheck.BLOCK) showPairBlocked(payload.origin)
                        else showPairReview(payload)
                    is Payload.SignTxRequest -> showMessage("That's a signing request", "This screen is for pairing. To sign, go back and choose Sign a transaction.")
                    else -> showMessage("Not a pairing request", "That QR code comes from a vault, not the dashboard.")
                }
            }
        }
    }

    private fun showPairReview(request: Payload.PairRequest, error: String? = null) {
        if (mustWait { showPairReview(request) }) return
        val field = ui.passwordField("Vault passphrase")
        val check = Pairing.checkOrigin(request.origin, isDebuggable())
        if (check == Pairing.OriginCheck.BLOCK) return showPairBlocked(request.origin)
        show(
            listOf(
                ui.title("Pair with ${request.origin}?"),
                if (check == Pairing.OriginCheck.OFFICIAL) null
                else ui.error("This request names ${request.origin}, not $OFFICIAL_ORIGIN. Development build: allowed for testing. Release builds refuse it."),
                ui.body("Pairing gives ${request.origin} your vault's address (account 1) and proves this vault holds its key. Then the dashboard can show your balances and prepare transactions for you to review here."),
                ui.note("Pairing can't move funds. Every transaction still needs your approval on this device."),
                // A phishing page can show a real code it fetched itself (docs/SECURITY.md, "The bridge").
                ui.note("Only pair with a code from isol8.app in a browser you opened yourself, not one from a link or message."),
                error?.let { ui.error(it) },
                field,
                ui.button("Pair") {
                    val passphrase = field.text.toString()
                    field.text.clear()
                    if (!gate()) return@button
                    working("Signing the pairing. This takes a few seconds.", {
                        val secret = openVault(passphrase)
                        try {
                            val signer = SolanaKeys.signer(Bip39.entropyToMnemonic(secret.entropy), secret.bip39Passphrase)
                            Payload.encode(Pairing.respond(signer, request, 0, APP_VERSION_MAJOR, APP_VERSION_MINOR)) to
                                Base58.encode(signer.publicKey)
                        } finally {
                            secret.wipe()
                        }
                    }) { result ->
                        result.fold(
                            onSuccess = { (response, address) -> showPairResponse(request.origin, response, address) },
                            onFailure = { e ->
                                when {
                                    e is VaultEnvelopeException && e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED ->
                                        showPairReview(request, "Wrong passphrase.")
                                    e is KeyPermanentlyInvalidatedException ->
                                        showMessage("This vault can't be opened", "This device's vault key is no longer valid, for example because the screen lock was removed. Delete the vault and restore from your recovery phrase.")
                                    else -> showPairReview(request, e.message ?: e.javaClass.simpleName)
                                }
                            },
                        )
                    }
                },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun showPairBlocked(origin: String): Unit = show(
        listOf(
            ui.title("Pairing refused"),
            ui.error("This request names $origin. isol8 vault only pairs with $OFFICIAL_ORIGIN."),
            ui.body("If a site sent you here, it may be pretending to be isol8. Go to $OFFICIAL_ORIGIN by typing the address yourself, and pair from there."),
            ui.button("OK") { showHome() },
        ),
    )

    private fun showPairResponse(origin: String, response: ByteArray, address: String) = showQr(
        "Scan this with the dashboard",
        "Point the camera on $origin at this code.",
        response,
        listOf(
            ui.heading("Paired address (account 1)"),
            ui.mono(address),
            ui.note("Check that the dashboard shows this same address."),
            ui.button("Done") { showHome() },
        ),
    )

    // ---------------------------------------------------------------- signing

    /**
     * Unlocking comes first, before the request exists: deriving the key takes seconds and typing a long passphrase
     * takes longer, and a recent-blockhash request (nonce activation) is only valid for about a minute from when the
     * dashboard builds it. The key then waits in [secrets] while the camera runs; Cancel, leaving the app or the
     * screen turning off wipes it, and so does signing or declining.
     */
    private fun showSignUnlock(error: String? = null) {
        if (!gate()) return
        if (mustWait { showSignUnlock() }) return
        val field = ui.passwordField("Vault passphrase")
        show(
            listOf(
                ui.title("Sign a transaction"),
                ui.body("Unlock first, then scan the request. Take your time: nothing on the dashboard is waiting yet."),
                error?.let { ui.error(it) },
                field,
                ui.button("Unlock and scan") {
                    val passphrase = field.text.toString()
                    field.text.clear()
                    if (!gate()) return@button
                    working("Unlocking. This takes a few seconds.", {
                        val secret = openVault(passphrase)
                        try {
                            SolanaKeys.signer(Bip39.entropyToMnemonic(secret.entropy), secret.bip39Passphrase)
                        } finally {
                            secret.wipe()
                        }
                    }) { result ->
                        result.fold(
                            onSuccess = { signer ->
                                secrets.signer = signer
                                showSignScan()
                            },
                            onFailure = { e ->
                                when {
                                    e is VaultEnvelopeException && e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED ->
                                        showSignUnlock("Wrong passphrase.")
                                    e is KeyPermanentlyInvalidatedException ->
                                        showMessage("This vault can't be opened", "This device's vault key is no longer valid, for example because the screen lock was removed. Delete the vault and restore from your recovery phrase.")
                                    else -> showSignUnlock(e.message ?: e.javaClass.simpleName)
                                }
                            },
                        )
                    }
                },
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    private fun showSignScan() {
        if (!gate()) return
        if (secrets.signer == null) return showSignUnlock()
        withCamera {
            if (!gate()) return@withCamera
            if (secrets.signer == null) return@withCamera showSignUnlock()
            showScan(
                "Vault unlocked: scan the request",
                "On isol8.app, open the transaction to sign, then point this camera at its QR code. Cancel locks the vault.",
            ) { bytes ->
                val payload = try {
                    Payload.decode(bytes)
                } catch (e: ProtocolException) {
                    return@showScan showMessage("Not a valid request", e.message ?: "The QR code couldn't be read.")
                }
                when (payload) {
                    is Payload.SignTxRequest -> checkSignRequest(payload)
                    is Payload.PairRequest -> showMessage("That's a pairing request", "To pair, go back and choose Pair with the isol8 dashboard.")
                    else -> showMessage("Not a signing request", "That QR code comes from a vault, not the dashboard.")
                }
            }
        }
    }

    private fun checkSignRequest(request: Payload.SignTxRequest) {
        val signer = secrets.signer ?: return showSignUnlock()
        working("Checking the request…", {
            // A damaged settings file stops here rather than signing without the address book's checks.
            Acceptance.evaluate(request, loadSettings().vaultState(listOf(signer.publicKey)))
        }) { result ->
            result.fold(
                onSuccess = { decision ->
                    when (decision) {
                        is Decision.Accept -> showSignReview(request, decision)
                        is Decision.Decline -> showDeclined(request, decision.reason, decision.why)
                    }
                },
                onFailure = { e ->
                    showMessage("Couldn't check the request", e.message ?: e.javaClass.simpleName)
                },
            )
        }
    }

    private fun showSignReview(request: Payload.SignTxRequest, decision: Decision.Accept) {
        val signer = secrets.signer ?: return showHome()
        val views = mutableListOf<View?>(ui.title("Review the transaction"))
        // A lookalike or a near-miss destination: declining becomes the default (below).
        val lookalike = decision.warnings.any { it is Warning.LookalikeAddress || it is Warning.NearMissAddress }
        val swap = decision.actions.filterIsInstance<Action.Swap>().firstOrNull()
        fun outName(s: Action.Swap) = if (s.outMint == Acceptance.WSOL_MINT) "SOL" else s.outSymbol ?: "tokens"
        for (w in decision.warnings) {
            views += when (w) {
                is Warning.HighFee -> ui.error("High fee. This transaction can cost up to ${Amounts.sol(w.maxFeeLamports)} in fees. Your limit for a warning is ${Amounts.sol(w.thresholdLamports)}.")
                is Warning.LookalikeAddress -> ui.error(
                    "Lookalike address. ${w.address.chunked(4).joinToString(" ")} looks like your saved \"${w.label}\" " +
                        "(${w.resembles.chunked(4).joinToString(" ")}): same first and last 4 characters, different in between. Scammers make these on purpose.",
                )
                is Warning.NearMissAddress -> ui.error(
                    "Almost your saved \"${w.label}\". ${w.address.chunked(4).joinToString(" ")} is ${w.differences} character" +
                        "${if (w.differences == 1) "" else "s"} different from it (${w.resembles.chunked(4).joinToString(" ")}). " +
                        "If you meant to send there, a character is wrong. Funds sent to a wrong address can't be recovered.",
                )
                is Warning.HighSlippage -> ui.error(
                    "High slippage. This swap accepts a price up to ${Amounts.format(w.slippageBps.toString(), 2)}% worse than quoted" +
                        (swap?.let { s -> ": you could receive as little as ${Amounts.format(s.minOutAmount, s.outDecimals)} ${outName(s)} instead of the quoted ${Amounts.format(s.quotedOutAmount, s.outDecimals)}" } ?: "") +
                        ". Above ${Amounts.format(w.thresholdBps.toString(), 2)}% is unusual outside very thin markets.",
                )
            }
        }
        // Extreme slippage is usually a typo (50 for 5): signing needs a deliberate tick first. Not a block: thin markets
        // sometimes need it.
        val accept = if (swap != null && swap.slippageBps >= EXTREME_SLIPPAGE_BPS) {
            ui.checkbox("I accept getting up to ${Amounts.format(swap.slippageBps.toString(), 2)}% less than quoted") { }
        } else null
        if (decision.actions.isEmpty() && decision.durableNonce) {
            // A nonce-only advance: how the dashboard cancels something signed earlier and not yet sent.
            views += ui.card(
                ui.text("Cancel", 22f, bold = true),
                ui.body("Only use up this vault's current nonce. Nothing is sent."),
                ui.note("This cancels any other transaction you signed with the same nonce that hasn't gone through yet: it can never be sent after this."),
            )
        } else if (decision.actions.isEmpty()) {
            views += ui.card(ui.body("Nothing except pay the network fee."))
        }
        decision.actions.forEachIndexed { i, a -> views += ui.card(actionViews(i + 1, a)) }
        views += ui.card(
            ui.row("From", "This vault (account 1)"),
            ui.address(Base58.encode(signer.publicKey)).apply { setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 16f); setTextColor(Palette.TEXT_2) },
            ui.divider(),
            ui.row("Network fee", "at most ${Amounts.sol(decision.maxFeeLamports)}"),
            ui.row("Valid until", if (decision.durableNonce) "sent or cancelled" else "about a minute"),
            decision.nonceAccount?.let { ui.note("Nonce account ${it.chunked(4).joinToString(" ")}") },
        )
        views += ui.note("Check every address against where you meant to send. The dashboard can't change what you approve here.")
        val sign = {
            if (gate()) {
                val key = secrets.signer
                if (key == null) showHome() else {
                    val response = try {
                        TxSigning.respond(key, request)
                    } catch (e: ProtocolException) {
                        null.also { showMessage("Couldn't sign", e.message ?: "Signing failed.") }
                    } finally {
                        secrets.wipe()
                    }
                    if (response != null) showQr(
                        "✓ Signed",
                        "Point the dashboard's camera at this code. It changes every moment: hold steady until the dashboard says it's read. It holds only the signature, which works for this exact transaction and nothing else.",
                        Payload.encode(response),
                        listOf(ui.primaryButton("Done") { showHome() }),
                    )
                }
            }
        }
        val decline = {
            secrets.wipe()
            showDeclined(request, Acceptance.DECLINE_USER, "You declined this transaction.")
        }
        val hold = if (lookalike) ui.holdButton("I checked it: hold to sign anyway", danger = true) { sign() } else ui.holdButton("Hold to sign") { sign() }
        if (accept != null) {
            hold.isEnabled = false
            accept.setOnCheckedChangeListener { _, checked -> hold.isEnabled = checked }
            views += accept
        }
        if (lookalike) {
            // With a lookalike or near-miss address, declining is the safe default: the big button.
            views += ui.primaryButton("Decline (recommended)") { decline() }.apply {
                background = android.graphics.drawable.GradientDrawable().apply { setColor(Palette.TEXT); cornerRadius = ui.dp(20).toFloat() }
                setTextColor(Palette.BG)
            }
            views += hold
        } else {
            views += hold
            views += ui.button("Decline") { decline() }
        }
        show(views)
    }

    private fun actionViews(n: Int, a: Action): List<View?> = when (a) {
        is Action.SolTransfer -> listOf(
            ui.amount("Send", Amounts.sol(a.lamports)),
            ui.note("To"),
            ui.address(a.to),
            a.toLabel?.let { ui.good("Saved as \"$it\"") },
        )
        is Action.TokenTransfer -> listOf(
            ui.amount("Send", "${Amounts.format(a.amount, a.decimals)} ${a.mintSymbol ?: "tokens"}"),
            ui.note("To"),
            ui.address(a.toOwner),
            a.toLabel?.let { ui.good("Saved as \"$it\"") },
            if (a.mintSymbol == null) ui.note("Token (mint), not one this vault can name:") else null,
            if (a.mintSymbol == null) ui.address(a.mint) else null,
            ui.note("Into their token account ${a.toAccount}"),
        )
        // The rent isn't in the instruction and the vault is offline, so no amount: it changes with the network.
        is Action.CreateTokenAccount -> if (a.owner == a.rentPayer) listOf(
            ui.body("$n. Open this vault's own ${a.mintSymbol ?: "token"} account, if it doesn't have one yet. Its rent, a small amount of SOL, stays in your account."),
            ui.note("Mint ${a.mint}"),
        ) else listOf(
            ui.body("$n. Open a ${a.mintSymbol ?: "token"} account for the recipient, if they don't have one yet. This vault pays its rent: a small amount of SOL, on top of the network fee, that stays with the recipient's account and doesn't come back to you."),
            ui.note("Owner ${a.owner}, mint ${a.mint}"),
        )
        is Action.WrapSol -> listOf(
            ui.body("$n. Wrap ${Amounts.sol(a.lamports)} for the swap: it moves into this vault's own wrapped-SOL account, not to anyone else."),
        )
        is Action.UnwrapSol -> listOf(
            ui.body("$n. Unwrap: close this vault's wrapped-SOL account. Its wrapped SOL and rent come back to this vault as SOL."),
        )
        is Action.WithdrawNonceAccount -> listOf(
            ui.body("$n. Withdraw ${Amounts.sol(a.lamports)} from a nonce account back to this vault. Withdrawing all of it closes the account."),
            ui.note("Nonce account ${a.account}. Afterwards the vault needs a new nonce account (an activation) before it can sign at its own pace again."),
        )
        is Action.CloseTokenAccount -> listOf(
            ui.body("$n. Close an empty token account and return its rent to this vault."),
            ui.note("Account ${a.account}. The token program refuses to close an account that still holds tokens, so nothing else can leave."),
        )
        is Action.Swap -> {
            fun name(symbol: String?, mint: String) = if (mint == Acceptance.WSOL_MINT) "SOL" else symbol ?: "tokens"
            val inName = name(a.inSymbol, a.inMint)
            val outName = name(a.outSymbol, a.outMint)
            listOf(
                ui.amount("You pay", "${Amounts.format(a.inAmount, a.inDecimals)} $inName"),
                ui.text("↓", 22f, bold = true).apply { setTextColor(Palette.ACCENT_TEXT) },
                ui.amount("You receive at least", "${Amounts.format(a.minOutAmount, a.outDecimals)} $outName"),
                ui.note("Quoted: ${Amounts.format(a.quotedOutAmount, a.outDecimals)} $outName. If the price moves more than ${Amounts.format(a.slippageBps.toString(), 2)}% before it lands, the whole transaction fails and nothing is swapped."),
                if (a.feeBps > 0) ui.note("isol8 fee: ${Amounts.format(a.feeBps.toString(), 2)}%, taken in ${if (a.feeMint == a.inMint) inName else outName}, included in the amounts above.") else null,
                if (a.inSymbol == null) ui.note("Selling (mint, not one this vault can name):") else null,
                if (a.inSymbol == null) ui.address(a.inMint) else null,
                if (a.outSymbol == null) ui.note("Buying (mint, not one this vault can name; check it's the token you want):") else null,
                if (a.outSymbol == null) ui.address(a.outMint) else null,
                ui.note("Through Jupiter, which must pay at least the minimum into this vault's own account or fail."),
            )
        }
        is Action.Memo -> listOf(
            ui.body("$n. Attach this note (text written by whoever made the request, not checked by the vault):"),
            ui.mono("\"${a.text}\""),
        )
        is Action.CreateNonceAccount -> listOf(
            ui.body("$n. Set up this vault's nonce account (${a.seed}), depositing ${Amounts.sol(a.lamports)}. It lets future transactions stay valid until you broadcast them."),
            ui.address(a.account),
        )
    }

    private fun declineText(reason: Int): String = when (reason) {
        Acceptance.DECLINE_USER -> "You declined it."
        Acceptance.DECLINE_UNSUPPORTED -> "It uses a program or instruction this vault doesn't support."
        Acceptance.DECLINE_LOOKUP_TABLES -> "It uses address lookup tables, which this vault can't show in full."
        Acceptance.DECLINE_UNKNOWN_SIGNER -> "It asks for a key this vault doesn't hold. It may be meant for another vault, or another account."
        Acceptance.DECLINE_MALFORMED -> "The transaction is malformed."
        Acceptance.DECLINE_RULE -> "It breaks one of the vault's safety rules."
        Acceptance.DECLINE_DEVICE_ONLINE -> "This device isn't offline."
        else -> "Reason $reason."
    }

    /** Shows why, then a SIGN_TX_DECLINED code so the dashboard can explain and stop waiting. */
    private fun showDeclined(request: Payload.SignTxRequest, reason: Int, why: String) {
        secrets.wipe()
        showQr(
            if (reason == Acceptance.DECLINE_USER) "Declined" else "The vault refused this transaction",
            declineText(reason) + if (reason == Acceptance.DECLINE_USER) "" else " Details: $why",
            Payload.encode(TxSigning.decline(request, reason)),
            listOf(
                ui.note("Show this code to the dashboard so it knows nothing was signed."),
                ui.button("Done") { showHome() },
            ),
        )
    }

    // ---------------------------------------------------------------- wrong passphrases (docs/SECURITY.md, "The key")

    /** Unreadable counts as none: changing this file at all takes root, which would bypass any count anyway. */
    private fun loadAttempts(): PassphraseAttempts = try {
        if (attemptsStore.exists()) PassphraseAttempts.decode(attemptsStore.load()) else PassphraseAttempts()
    } catch (e: Exception) {
        PassphraseAttempts()
    }

    /** The Keystore key only works while the phone is unlocked, so this can fail with the screen off. */
    private fun saveAttempts(attempts: PassphraseAttempts) {
        runCatching { if (attempts == PassphraseAttempts()) attemptsStore.deleteFile() else attemptsStore.save(attempts.encode()) }
    }

    /** Opens the vault with [passphrase], counting a wrong one. Runs on the worker thread. */
    private fun openVault(passphrase: String): VaultSecret {
        val secret = try {
            VaultEnvelope.open(store.load(), passphrase)
        } catch (e: VaultEnvelopeException) {
            if (e.reason == VaultEnvelopeException.Reason.WRONG_PASSPHRASE_OR_TAMPERED) saveAttempts(loadAttempts().failed())
            throw e
        }
        if (attemptsStore.exists()) saveAttempts(PassphraseAttempts())
        return secret
    }

    /**
     * After too many wrong passphrases, shows the wait counting down, then [then]. Returns true while waiting.
     * The wait counts only while this screen is open, so changing the clock or restarting the phone doesn't skip it.
     */
    private fun mustWait(then: () -> Unit): Boolean {
        var attempts = loadAttempts()
        if (!attempts.mustWait) return false
        val clock = ui.text("", 32f, bold = true)
        fun label() {
            val s = attempts.waitSeconds
            clock.text = if (s >= 3600) "%d:%02d:%02d".format(s / 3600, s / 60 % 60, s % 60) else "%d:%02d".format(s / 60, s % 60)
        }
        label()
        show(
            listOf(
                ui.title("Too many wrong passphrases"),
                ui.body("You can try again when this reaches zero. Keep the vault open: the wait only counts down while this screen is showing."),
                clock,
                ui.note("Forgot your passphrase? Delete the vault from Home and restore it from your recovery phrase."),
                ui.button("Cancel") { showHome() },
            ),
        )
        var ticks = 0
        val tick = object : Runnable {
            override fun run() {
                if (!clock.isAttachedToWindow) return saveAttempts(attempts) // left this screen: keep what's left
                attempts = attempts.waited(1)
                if (!attempts.mustWait) {
                    saveAttempts(attempts)
                    return then()
                }
                if (++ticks % 5 == 0) saveAttempts(attempts)
                label()
                clock.postDelayed(this, 1000)
            }
        }
        clock.postDelayed(tick, 1000)
        return true
    }

    // ---------------------------------------------------------------- delete

    /**
     * Deleting the vault from this phone. No passphrase: Android's own uninstall can't be guarded either, and the usual
     * reason is a forgotten passphrase. What matters is the recovery phrase, so that's what it asks about, then a hold.
     */
    private fun showDelete(@Suppress("UNUSED_PARAMETER") armed: Boolean) {
        val hold = ui.holdButton("Hold to delete this vault", holdMs = 3000, danger = true) {
            settingsStore.deleteFile()
            attemptsStore.deleteFile()
            store.delete()
            showMessage(
                "Vault deleted",
                "The vault and its key are gone from this phone. Your coins are still on Solana: restore them any time with your recovery phrase, here or in any standard Solana wallet.",
            )
        }.apply { isEnabled = false }
        show(
            listOf(
                ui.title("Delete vault"),
                ui.body("This erases the vault, its key and its address book from this phone."),
                ui.card(
                    ui.text("Your coins don't live on this phone.", 18f, bold = true),
                    ui.note("They live on Solana. This vault only holds the key that moves them, and your recovery phrase is that key. With it you can restore everything, here or in any standard Solana wallet. Without it, nobody can ever move those coins again, isol8 included."),
                ),
                ui.checkbox("I have my recovery phrase written down") { checked -> hold.isEnabled = checked },
                ui.button("Not sure? Check my backup first") { showCheckIntro() },
                hold,
                ui.button("Cancel") { showHome() },
            ),
        )
    }

    /** A message ends the current flow: secrets go now, not when OK returns to Home. */
    private fun showMessage(title: String, message: String) {
        secrets.wipe()
        show(listOf(ui.title(title), ui.body(message), ui.button("OK") { showHome() }))
    }

    // ---------------------------------------------------------------- diagnostics

    private fun showDiagnostics() {
        val requested = requestedPermissions()
        val network = requested.filter { it in NETWORK_PERMISSIONS }
        // The OS may add its own entries (GrapheneOS adds toggles such as Sensors to every app): listed, not failed.
        val other = requested.filter { it !in NETWORK_PERMISSIONS && it !in EXPECTED_PERMISSIONS }
        val views = mutableListOf<View?>(
            ui.title("Diagnostics"),
            ui.heading("Network access"),
            ui.body(
                (if (network.isEmpty()) "✓ No network permission: no INTERNET, so Android blocks this app from opening any connection. It asks for the camera, to scan QR codes."
                else "✗ This app requests: ${network.joinToString()}. A real vault never does: don't trust this copy.") +
                    if (other.isEmpty()) "" else "\n\nAlso listed by the system (not in the app's own manifest, which allows only the camera): ${other.joinToString { it.substringAfterLast('.') }}.",
            ),
            ui.heading("Protocol core"),
            ui.body(coreSelfCheck()),
            ui.heading("Device"),
            ui.body("Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"),
        )
        if (settingsStore.exists()) {
            val ok = try {
                loadSettings()
                true
            } catch (e: Exception) {
                false
            }
            views += ui.heading("Address book")
            views += ui.body(if (ok) "✓ Readable." else "✗ Damaged. Signing is blocked until it's reset.")
            if (!ok) views += ui.button("Reset address book and fee warning") {
                settingsStore.deleteFile()
                showMessage("Reset", "The address book is empty and the fee warning is back to the default.")
            }
        }
        if (isDebuggable()) {
            val result = ui.body("Not run. It uses a throwaway key and file, deleted afterwards.")
            views += ui.heading("Storage self-test")
            views += result
            views += ui.button("Run storage self-test") {
                working("Running storage self-test…", { StorageSelfTest.run(applicationContext) }) { r ->
                    showMessage("Storage self-test", r.getOrElse { it.message ?: it.javaClass.simpleName })
                }
            }
        }
        views += ui.button("Device report") { showDeviceReport() }
        views += ui.button("Back") { showHome() }
        show(views)
    }

    /** Round-trips a pairing request through payload encoding, QR framing and Base45, as on a real scan. */
    private fun coreSelfCheck(): String = try {
        val request = Payload.PairRequest(sha256(utf8("isol8 self-check")), "isol8.app")
        val decoded = Payload.decode(Frames.decodeAll(Frames.encode(Payload.encode(request)))) as Payload.PairRequest
        val ok = decoded.origin == request.origin && decoded.challenge.contentEquals(request.challenge) &&
            Base45.decode(Base45.encode(request.challenge)).contentEquals(request.challenge)
        if (ok) "✓ Protocol version ${Frames.VERSION} loaded: framing, Base45 and payload decoding work on this device." else "✗ Self-check failed."
    } catch (e: Exception) {
        "✗ Self-check failed: ${e.message}"
    }

    private companion object {
        const val CAMERA_REQUEST = 1
        const val SCAN_RESET_MS = 30_000L
        const val OFFICIAL_ORIGIN = "isol8.app"
        /** At or above this slippage (15%), signing a swap needs a deliberate tick first. */
        const val EXTREME_SLIPPAGE_BPS = 1_500
        const val APP_VERSION_MAJOR = 0
        const val APP_VERSION_MINOR = 1
        val EXPECTED_PERMISSIONS = setOf(Manifest.permission.CAMERA)
        /** Anything that could reach a network or another device. The build already refuses them (app/build.gradle.kts). */
        val NETWORK_PERMISSIONS = setOf(
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.CHANGE_WIFI_MULTICAST_STATE",
            "android.permission.NEARBY_WIFI_DEVICES",
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH_ADVERTISE",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.NFC",
            "android.permission.UWB_RANGING",
        )
    }

    private fun requestedPermissions(): List<String> {
        val info: PackageInfo = if (Build.VERSION.SDK_INT >= 33) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
        }
        return info.requestedPermissions?.toList().orEmpty()
    }
}
