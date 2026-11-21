package app.isol8.vault.qr

import app.isol8.vault.core.Frames
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.LuminanceSource
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.decoder.Mode
import com.google.zxing.qrcode.encoder.Encoder

/** A QR code's modules, without a quiet zone: draw at least [QrCodes.QUIET_ZONE] light modules around it. */
class QrMatrix internal constructor(val size: Int, val version: Int, private val dark: BooleanArray) {
    fun isDark(x: Int, y: Int): Boolean = dark[y * size + x]
}

/**
 * QR codes for isol8 frames (PROTOCOL.md §3.1): alphanumeric mode, error correction level M.
 * Only ZXing's core encoder and decoder are used; drawing and camera handling are the app's.
 */
object QrCodes {
    const val QUIET_ZONE = 4

    /** The QR alphanumeric character set, which is also exactly Base45's alphabet. */
    private val ALPHANUMERIC = Regex("^[0-9A-Z $%*+\\-./:]+$")

    /**
     * Encodes [text] and checks that ZXing's own camera-style decoder reads the result back at several sizes.
     * Some data patterns confuse QR finder-pattern detection under the mask the encoder picks by default
     * (about 1 frame in 9 in testing, mostly frames with long runs of zero bytes), so the other seven
     * masks are tried in turn. Masks are a standard QR feature: every scanner reads all eight.
     */
    fun encode(text: String): QrMatrix {
        require(text.startsWith(Frames.PREFIX) && ALPHANUMERIC.matches(text)) { "not an isol8 frame" }
        val masks = listOf<Int?>(null) + (0..7)
        for (mask in masks) {
            val m = encodeWithMask(text, mask)
            if (readsBack(m, text)) return m
        }
        throw IllegalStateException("no QR mask produced a code that scans back")
    }

    /** A Solana address: Base58, 32 to 44 characters. */
    private val ADDRESS = Regex("^[1-9A-HJ-NP-Za-km-z]{32,44}$")

    /**
     * The vault's own Solana address as a QR code, for another wallet's scanner or to compare with the
     * dashboard's Receive code. Not an isol8 frame: level M, and the same scan-back check.
     */
    fun encodeAddress(address: String): QrMatrix {
        require(ADDRESS.matches(address)) { "not a Solana address" }
        for (mask in listOf<Int?>(null) + (0..7)) {
            val m = encodeWithMask(address, mask, mode = null) // the encoder picks the mode: byte, or numeric for all-digit addresses
            if (readsBack(m, address, anyCode = true)) return m
        }
        throw IllegalStateException("no QR mask produced a code that scans back")
    }

    internal fun encodeWithMask(text: String, mask: Int?, mode: Mode? = Mode.ALPHANUMERIC): QrMatrix {
        val hints = if (mask == null) emptyMap() else mapOf(EncodeHintType.QR_MASK_PATTERN to mask)
        val qr = Encoder.encode(text, ErrorCorrectionLevel.M, hints)
        if (mode != null) check(qr.mode == mode) { "expected $mode mode, got ${qr.mode}" }
        val m = qr.matrix
        val size = m.width
        return QrMatrix(size, qr.version.versionNumber, BooleanArray(size * size) { m.get(it % size, it / size).toInt() == 1 })
    }

    private fun readsBack(m: QrMatrix, text: String, anyCode: Boolean = false): Boolean {
        val scanner = QrScanner()
        return SELF_CHECK_SCALES.all { scale ->
            val (img, side) = render(m, scale)
            (if (anyCode) scanner.scanAnyLuminance(img, side, side, side) else scanner.scanLuminance(img, side, side, side)) == text
        }
    }

    private val SELF_CHECK_SCALES = 2..5

    /** Draws [m] as a grey image with the quiet zone, [scale] pixels per module. Returns the pixels and side length. */
    internal fun render(m: QrMatrix, scale: Int): Pair<ByteArray, Int> {
        val side = (m.size + 2 * QUIET_ZONE) * scale
        val img = ByteArray(side * side) { 0xE0.toByte() }
        for (py in 0 until side) {
            val my = py / scale - QUIET_ZONE
            if (my !in 0 until m.size) continue
            for (px in 0 until side) {
                val mx = px / scale - QUIET_ZONE
                if (mx in 0 until m.size && m.isDark(mx, my)) img[py * side + px] = 0x20
            }
        }
        return Pair(img, side)
    }
}

/**
 * Finds an isol8 frame in camera images. Not thread-safe: use one per scanning thread.
 * Anything that isn't an isol8 frame (other QR codes, unreadable images) returns null;
 * the frame's contents are validated later by [Frames].
 */
class QrScanner {
    private val reader = QRCodeReader()
    private val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))

    /** Scans the luminance (Y) plane of a camera frame; [rowStride] may exceed [width]. */
    fun scanLuminance(y: ByteArray, rowStride: Int, width: Int, height: Int): String? =
        scan(PlanarYUVLuminanceSource(y, rowStride, height, 0, 0, width, height, false), isol8Only = true)

    /** Like [scanLuminance] but returns any QR code's text (up to 512 characters), e.g. a wallet's address. */
    fun scanAnyLuminance(y: ByteArray, rowStride: Int, width: Int, height: Int): String? =
        scan(PlanarYUVLuminanceSource(y, rowStride, height, 0, 0, width, height, false), isol8Only = false)

    /** Why the last scan found nothing, for development diagnostics: an exception name or "not an isol8 code". */
    var lastMiss: String? = null
        private set

    private fun scan(source: LuminanceSource, isol8Only: Boolean): String? {
        val text = try {
            reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (e: ReaderException) {
            lastMiss = e.javaClass.simpleName
            null
        } catch (e: RuntimeException) {
            // A malformed image must never crash the vault; treat it as "nothing found".
            lastMiss = e.javaClass.simpleName
            null
        } finally {
            reader.reset()
        }
        if (text == null) return null
        if (text.length > MAX_TEXT || (isol8Only && !text.startsWith(Frames.PREFIX))) {
            lastMiss = "not an isol8 code"
            return null
        }
        lastMiss = null
        return text
    }

    private companion object {
        /** A full 256-byte chunk frame is 407 characters; anything far longer isn't ours. */
        const val MAX_TEXT = 512
    }
}
