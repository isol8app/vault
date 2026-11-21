package app.isol8.vault.qr

import app.isol8.vault.core.Frames
import app.isol8.vault.core.Payload
import app.isol8.vault.core.sha256
import app.isol8.vault.core.unhex
import app.isol8.vault.core.utf8
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Development tool: writes an HTML page of test QR codes for scanning with the vault on a test device.
 * Run with ./gradlew :qr:testPage. Test data only (the protocol vectors' public test keys).
 * Signing requests for a device's test vault come from protocol/scripts/device-requests.ts, if its output
 * is at build/test-page/device-requests.json.
 */
fun main(args: Array<String>) {
    val vectors = File(args[0])
    val out = File(args[1])
    val pairing = JSONObject(File(vectors, "pairing.json").readText())
    val txs = JSONArray(File(vectors, "transactions.json").readText())
    val multi = (0 until txs.length()).map { txs.getJSONObject(it) }.first { it.getJSONObject("request").getJSONArray("frames").length() > 1 }

    val device = args.getOrNull(2)?.let(::File)?.takeIf { it.exists() }?.let { JSONObject(it.readText()) }
    val cases = listOf(
        Triple("1. Pairing request from isol8.app", "The protocol's pairing test vector.", unhex(pairing.getJSONObject("request").getString("payload_hex"))),
        Triple("2. Pairing request from a lookalike site", "Origin isol8-app.example: the vault should warn.", Payload.encode(Payload.PairRequest(sha256(utf8("lookalike test")), "isol8-app.example"))),
        Triple("3. Signing request, ${multi.getJSONObject("request").getJSONArray("frames").length()} frames", "Animated at 4 frames per second: tests multi-part scanning (${multi.getString("name")}).", unhex(multi.getJSONObject("request").getString("payload_hex"))),
    ) + (device?.getJSONArray("requests")?.let { r ->
        (0 until r.length()).map { i ->
            val c = r.getJSONObject(i)
            Triple("${4 + i}. Sign: ${c.getString("name")}", "For ${device.getString("signer")}. Expect: ${c.getString("expect")}. Reference evaluator: ${c.getString("reference")}.", unhex(c.getString("payload_hex")))
        }
    } ?: emptyList())
    // Wallet receive codes (plain text, byte mode) for the address book.
    val addressSections = device?.optJSONArray("address_codes")?.let { a ->
        (0 until a.length()).joinToString("\n") { i ->
            val c = a.getJSONObject(i)
            val m = com.google.zxing.qrcode.encoder.Encoder.encode(c.getString("text"), com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.M).matrix
            val svg = svg(m.width) { x, y -> m.get(x, y).toInt() == 1 }
            """<section><h2>Address ${'A' + i}. ${c.getString("name")}</h2><p>${c.getString("text")}</p><div class="qr">$svg</div></section>"""
        }
    } ?: ""
    val sections = cases.joinToString("\n") { (title, note, payload) ->
        val svgs = Frames.encode(payload).map { f -> QrCodes.encode(f).let { m -> svg(m.size) { x, y -> m.isDark(x, y) } } }
        val frames = svgs.mapIndexed { i, s -> """<div class="f" style="display:${if (i == 0) "block" else "none"}">$s</div>""" }.joinToString("")
        """<section><h2>$title</h2><p>$note</p><div class="qr" data-n="${svgs.size}">$frames</div></section>"""
    }
    out.parentFile.mkdirs()
    out.writeText(
        """<!doctype html><html><head><meta charset="utf-8"><title>isol8 test QR codes</title>
<style>body{font:16px system-ui;margin:24px;background:#fff;color:#111}section{margin-bottom:48px}.qr svg{width:420px;height:420px}h2{margin:0 0 4px}p{margin:0 0 12px;color:#555}</style></head>
<body><h1>isol8 test QR codes</h1><p>Test data only. Scan with the vault on a test device.</p>
$sections
$addressSections
<script>for(const q of document.querySelectorAll('.qr')){const f=q.querySelectorAll('.f');if(f.length<2)continue;let i=0;setInterval(()=>{f[i].style.display='none';i=(i+1)%f.length;f[i].style.display='block'},250)}</script>
</body></html>""",
    )
    println("wrote ${out.absolutePath}")
}

private fun svg(size: Int, dark: (Int, Int) -> Boolean): String {
    val n = size + 2 * QrCodes.QUIET_ZONE
    val path = StringBuilder()
    for (y in 0 until size) for (x in 0 until size) if (dark(x, y)) path.append("M${x + QrCodes.QUIET_ZONE} ${y + QrCodes.QUIET_ZONE}h1v1h-1z")
    return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 $n $n" shape-rendering="crispEdges"><rect width="$n" height="$n" fill="#fff"/><path d="$path" fill="#000"/></svg>"""
}
