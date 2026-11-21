package app.isol8.vault.qr

import app.isol8.vault.core.Frames
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class QrCodesTest {
    private val dir = File(System.getProperty("isol8.vectors"))
    private fun json(name: String) = JSONObject(File(dir, name).readText())

    /** Every frame in the shared vectors, requests and responses. */
    private fun vectorFrames(): List<String> {
        val out = mutableListOf<String>()
        fun add(a: JSONArray) = (0 until a.length()).forEach { out += a.getString(it) }
        val pairing = json("pairing.json")
        add(pairing.getJSONObject("request").getJSONArray("frames"))
        add(pairing.getJSONObject("response").getJSONArray("frames"))
        val txs = JSONArray(File(dir, "transactions.json").readText())
        for (i in 0 until txs.length()) {
            val t = txs.getJSONObject(i)
            add(t.getJSONObject("request").getJSONArray("frames"))
            t.optJSONObject("response")?.let { add(it.getJSONArray("frames")) }
        }
        return out
    }

    /** Draws a matrix as a camera-like grey image: quiet zone, [scale] pixels per module, optional rotation. */
    private fun render(m: QrMatrix, scale: Int, rotate: Boolean = false): Triple<ByteArray, Int, Int> {
        val side = (m.size + 2 * QrCodes.QUIET_ZONE) * scale
        val img = ByteArray(side * side) { 0xE0.toByte() }
        for (py in 0 until side) for (px in 0 until side) {
            val mx = px / scale - QrCodes.QUIET_ZONE
            val my = py / scale - QrCodes.QUIET_ZONE
            if (mx in 0 until m.size && my in 0 until m.size && m.isDark(mx, my)) {
                val (x, y) = if (rotate) Pair(side - 1 - py, px) else Pair(px, py)
                img[y * side + x] = 0x20
            }
        }
        return Triple(img, side, side)
    }

    @Test
    fun everyVectorFrameRoundTrips() {
        val frames = vectorFrames()
        assertTrue(frames.size > 40, "expected the full vector set, got ${frames.size}")
        val scanner = QrScanner()
        for (f in frames) {
            val m = QrCodes.encode(f)
            val (img, w, h) = render(m, scale = 3)
            assertEquals(f, scanner.scanLuminance(img, w, w, h), "frame did not survive a QR round trip: ${f.take(30)}")
        }
    }

    @Test
    fun fullFrameFitsVersion12AtLevelM() {
        val full = Frames.encode(Random(7).nextBytes(Frames.MAX_CHUNK * 2))
        assertEquals(407, full[0].length)
        val m = QrCodes.encode(full[0])
        assertEquals(12, m.version)
        assertEquals(65, m.size)
    }

    @Test
    fun rotatedAndPaddedImagesStillScan() {
        val f = Frames.encode(Random(1).nextBytes(300))[0]
        val (img, w, h) = render(QrCodes.encode(f), scale = 4, rotate = true)
        // Simulate a camera row stride wider than the image.
        val stride = w + 64
        val padded = ByteArray(stride * h) { 0x80.toByte() }
        for (y in 0 until h) System.arraycopy(img, y * w, padded, y * stride, w)
        assertEquals(f, QrScanner().scanLuminance(padded, stride, w, h))
    }

    /** Random payloads, many with long zero runs like real transactions: every frame must scan at every self-check size. */
    @Test
    fun randomFramesAlwaysScan() {
        val rnd = Random(42)
        val scanner = QrScanner()
        var frames = 0
        repeat(150) {
            val len = 1 + rnd.nextInt(600)
            val payload = if (rnd.nextBoolean()) rnd.nextBytes(len) else ByteArray(len).also { b -> rnd.nextBytes(b, 0, len / 3) }
            for (f in Frames.encode(payload)) {
                val m = QrCodes.encode(f)
                for (scale in 2..6) {
                    val (img, side) = QrCodes.render(m, scale)
                    assertEquals(f, scanner.scanLuminance(img, side, side, side), "scale $scale")
                }
                frames++
            }
        }
        assertTrue(frames > 150)
    }

    @Test
    fun otherQrCodesAreIgnored() {
        val (img, w, h) = render(QrCodes.encodeWithMask("HTTPS://EXAMPLE.COM/ISOL8:", null), scale = 3)
        assertNull(QrScanner().scanLuminance(img, w, w, h))
        assertNull(QrScanner().scanLuminance(ByteArray(200 * 200) { Random(3).nextInt().toByte() }, 200, 200, 200))
    }

    /** The address book reads wallets' receive codes, which aren't isol8 frames. */
    @Test
    fun anyTextModeReadsOtherCodes() {
        val text = "solana:icrGKa8xXzoqyADEbTQTzehtbXasoNDnvA5eetr6Q5C?label=Desk"
        // Wallets use byte mode (lowercase letters), so build it with ZXing directly, not the isol8 encoder.
        val qr = com.google.zxing.qrcode.encoder.Encoder.encode(text, com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M).matrix
        val size = qr.width
        val side = (size + 8) * 3
        val img = ByteArray(side * side) { 0xE0.toByte() }
        for (py in 0 until side) for (px in 0 until side) {
            val mx = px / 3 - 4
            val my = py / 3 - 4
            if (mx in 0 until size && my in 0 until size && qr.get(mx, my).toInt() == 1) img[py * side + px] = 0x20
        }
        val w = side
        val h = side
        assertEquals(text, QrScanner().scanAnyLuminance(img, w, w, h))
        assertNull(QrScanner().scanLuminance(img, w, w, h))
    }

    @Test
    fun `an address QR reads back as the address, and only addresses get one`() {
        for (address in listOf("oEGXn2LVvr43XTGtdh1JZzD3e8FAutjFzyBgCa7R7iw", "11111111111111111111111111111111", "So11111111111111111111111111111111111111112")) {
            val m = QrCodes.encodeAddress(address)
            val (img, side) = QrCodes.render(m, 4)
            assertEquals(address, QrScanner().scanAnyLuminance(img, side, side, side))
            assertNull(QrScanner().scanLuminance(img, side, side, side), "not an isol8 frame, so the frame scanner ignores it")
        }
        for (bad in listOf("", "0OIl", "https://isol8.app", "ISOL8:ABC", "x".repeat(45))) {
            kotlin.test.assertFailsWith<IllegalArgumentException> { QrCodes.encodeAddress(bad) }
        }
    }
}
