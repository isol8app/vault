package app.isol8.vault

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.view.View
import app.isol8.vault.qr.QrCodes
import app.isol8.vault.qr.QrMatrix

/**
 * Shows isol8 QR frames, black on white whatever the theme. Several frames loop at about
 * 4 per second (PROTOCOL.md §3.3) until the view leaves the screen.
 */
class QrView(context: Context, private val frames: List<QrMatrix>) : View(context) {
    private val paint = Paint().apply { color = Color.BLACK; isAntiAlias = false }
    private var index = 0

    private val advance = object : Runnable {
        override fun run() {
            index = (index + 1) % frames.size
            invalidate()
            postDelayed(this, FRAME_MS)
        }
    }

    init {
        require(frames.isNotEmpty())
        setBackgroundColor(Color.WHITE)
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        if (frames.size > 1) postDelayed(advance, FRAME_MS)
    }

    override fun onDetachedFromWindow() {
        removeCallbacks(advance)
        super.onDetachedFromWindow()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val width = MeasureSpec.getSize(widthMeasureSpec)
        val side = minOf(width, (resources.displayMetrics.heightPixels * 0.6f).toInt())
        setMeasuredDimension(side, side)
    }

    override fun onDraw(canvas: Canvas) {
        val m = frames[index]
        val modules = m.size + 2 * QrCodes.QUIET_ZONE
        // Whole pixels per module keep every module the same size, which scanners prefer.
        val cell = minOf(width, height) / modules
        if (cell < 1) return
        val offset = (minOf(width, height) - cell * modules) / 2 + QrCodes.QUIET_ZONE * cell
        for (y in 0 until m.size) {
            for (x in 0 until m.size) {
                if (m.isDark(x, y)) {
                    val left = (offset + x * cell).toFloat()
                    val top = (offset + y * cell).toFloat()
                    canvas.drawRect(left, top, left + cell, top + cell, paint)
                }
            }
        }
    }

    private companion object {
        const val FRAME_MS = 250L
    }
}
