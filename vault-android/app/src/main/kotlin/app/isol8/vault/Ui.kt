package app.isol8.vault

import android.app.Activity
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.graphics.drawable.ClipDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.graphics.drawable.StateListDrawable
import android.os.Build
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/**
 * The vault's look: dark, high contrast, large type. Every text colour clears WCAG AA on its background by a wide
 * margin (body about 17:1, secondary about 11:1, smallest labels about 8:1), because the vault is where people read
 * every detail before money moves.
 */
object Palette {
    const val BG = 0xFF06080D.toInt()
    const val SURFACE = 0xFF111725.toInt()
    const val LINE = 0xFF2A3550.toInt()
    const val DIVIDER = 0xFF222B40.toInt()
    const val TEXT = 0xFFF5F7FB.toInt()
    const val TEXT_2 = 0xFFC9D1DE.toInt()
    const val LABEL = 0xFFAAB4C4.toInt()
    const val ACCENT = 0xFF4F46E5.toInt()
    const val ACCENT_DARK = 0xFF3730A3.toInt()
    const val ACCENT_TEXT = 0xFFB4BFFF.toInt()
    const val GOOD_BG = 0xFF0F2A1C.toInt()
    const val GOOD_LINE = 0xFF34D399.toInt()
    const val GOOD_TEXT = 0xFFA7F3C9.toInt()
    const val BAD_BG = 0xFF3B0D12.toInt()
    const val BAD_LINE = 0xFFEF4444.toInt()
    const val BAD_TEXT = 0xFFFECACA.toInt()
    const val WARN_BG = 0xFF3A2A06.toInt()
    const val WARN_LINE = 0xFFF59E0B.toInt()
    const val WARN_TEXT = 0xFFFDE68A.toInt()
}

/** Small view builders. Plain Android framework views: no AndroidX, no UI libraries. */
class Ui(private val activity: Activity) {
    fun dp(v: Int) = (v * activity.resources.displayMetrics.density).toInt()

    private fun rounded(fill: Int, radiusDp: Int, stroke: Int? = null, strokeDp: Int = 1) = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(radiusDp).toFloat()
        if (stroke != null) setStroke(dp(strokeDp), stroke)
    }

    private fun LinearLayout.LayoutParams.spaced(top: Int = 10) = apply { topMargin = dp(top) }

    // ---------------------------------------------------------------- text

    fun title(s: String) = text(s, 28f, bold = true).apply { setTextColor(Palette.TEXT) }
    fun heading(s: String) = text(s, 14f, bold = true).apply {
        setTextColor(Palette.LABEL)
        setPadding(0, dp(22), 0, dp(6))
        isAllCaps = true
        letterSpacing = 0.08f
    }
    fun body(s: String) = text(s, 17f)
    fun note(s: String) = text(s, 15f).apply { setTextColor(Palette.TEXT_2) }
    fun error(s: String) = box(s, Palette.BAD_BG, Palette.BAD_LINE, Palette.BAD_TEXT)
    fun warning(s: String) = box(s, Palette.WARN_BG, Palette.WARN_LINE, Palette.WARN_TEXT)
    fun good(s: String) = box(s, Palette.GOOD_BG, Palette.GOOD_LINE, Palette.GOOD_TEXT)
    fun mono(s: String) = text(s, 18f).apply {
        typeface = Typeface.MONOSPACE
        setTextIsSelectable(false)
        setLineSpacing(dp(4).toFloat(), 1f)
    }

    fun text(s: String, sizeSp: Float, bold: Boolean = false) = TextView(activity).apply {
        text = s
        setTextColor(Palette.TEXT)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setLineSpacing(dp(2).toFloat(), 1f)
        setPadding(0, dp(4), 0, dp(4))
    }

    /** A big amount with its label above: "You pay" / "2.5 SOL". */
    fun amount(label: String, value: String): LinearLayout = column(
        text(label, 15f).apply { setTextColor(Palette.TEXT_2) },
        text(value, 32f, bold = true).apply { setPadding(0, 0, 0, dp(2)) },
    )

    /** A coloured panel with bold first line and wrapped text: errors, warnings, good news. */
    fun box(s: String, fill: Int, line: Int, textColor: Int) = text(s, 16f, bold = true).apply {
        setTextColor(textColor)
        background = rounded(fill, 18, line, 2)
        setPadding(dp(16), dp(14), dp(16), dp(14))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(12)
    }

    /** A rounded pill: "✓ Offline" in green, or a warning in red. */
    fun pill(s: String, ok: Boolean) = text(s, 15f, bold = true).apply {
        setTextColor(if (ok) Palette.GOOD_TEXT else Palette.BAD_TEXT)
        background = rounded(if (ok) Palette.GOOD_BG else Palette.BAD_BG, 999, if (ok) Palette.GOOD_LINE else Palette.BAD_LINE)
        setPadding(dp(12), dp(6), dp(12), dp(6))
    }

    // ---------------------------------------------------------------- layout

    fun column(vararg views: View?): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        views.filterNotNull().forEach(::addView)
    }

    /** A rounded card holding [views], full width. */
    fun card(views: List<View?>): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(Palette.SURFACE, 22, Palette.LINE)
        setPadding(dp(18), dp(14), dp(18), dp(14))
        views.filterNotNull().forEach(::addView)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(12)
    }
    fun card(vararg views: View?) = card(views.toList())

    /** A thin rule inside a card. */
    fun divider() = View(activity).apply {
        setBackgroundColor(Palette.DIVIDER)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, dp(1)).apply { topMargin = dp(8); bottomMargin = dp(8) }
    }

    /** "Label ............ value" on one line, for details inside a card. */
    fun row(label: String, value: String): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(6), 0, dp(6))
        addView(text(label, 16f).apply { setTextColor(Palette.TEXT_2) }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        addView(text(value, 16f).apply { gravity = Gravity.END }, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1.4f))
    }

    /** A check result: a round tick or cross, a bold line, and what to do. ok = null: couldn't check. */
    fun check(ok: Boolean?, title: String, detail: String?): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.HORIZONTAL
        setPadding(0, dp(10), 0, dp(10))
        val (fill, line, mark) = when (ok) {
            true -> Triple(Palette.GOOD_BG, Palette.GOOD_LINE, "✓")
            false -> Triple(Palette.BAD_BG, Palette.BAD_LINE, "✕")
            null -> Triple(Palette.WARN_BG, Palette.WARN_LINE, "?")
        }
        val badge = text(mark, 15f, bold = true).apply {
            setTextColor(if (ok == true) Palette.GOOD_TEXT else if (ok == false) Palette.BAD_TEXT else Palette.WARN_TEXT)
            gravity = Gravity.CENTER
            setPadding(0, 0, 0, 0)
            background = rounded(fill, 999, line, 2)
            contentDescription = when (ok) { true -> "Passed"; false -> "Failed"; null -> "Couldn't check" }
        }
        addView(badge, LinearLayout.LayoutParams(dp(30), dp(30)).apply { marginEnd = dp(14); topMargin = dp(2) })
        addView(
            column(
                text(title, 17f, bold = ok != true),
                detail?.let { text(it, 15f).apply { setTextColor(if (ok == false) Palette.BAD_TEXT else Palette.TEXT_2) } },
            ),
            LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f),
        )
    }

    // ---------------------------------------------------------------- buttons

    /** A secondary button: outlined, full width. */
    fun button(label: String, enabled: Boolean = true, onClick: () -> Unit) = styled(
        Button(activity), label, enabled, Palette.SURFACE, Palette.LINE, Palette.TEXT, 17f,
    ).apply { setOnClickListener { onClick() } }

    /** The main action on a screen: filled indigo, large. */
    fun primaryButton(label: String, enabled: Boolean = true, onClick: () -> Unit) = styled(
        Button(activity), label, enabled, Palette.ACCENT, null, 0xFFFFFFFF.toInt(), 19f, padV = 18,
    ).apply { setOnClickListener { onClick() } }

    /** A quiet choice: no outline, accent text. For the option most people shouldn't need. */
    fun textButton(label: String, onClick: () -> Unit) = Button(activity).apply {
        text = label
        isAllCaps = false
        stateListAnimator = null
        background = null
        setTextColor(Palette.ACCENT_TEXT)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 15f)
        setPadding(dp(8), dp(10), dp(8), dp(10))
        minHeight = dp(44)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(4)
        setOnClickListener { onClick() }
    }

    /** A careful action: outlined in red. */
    fun dangerButton(label: String, enabled: Boolean = true, onClick: () -> Unit) = styled(
        Button(activity), label, enabled, Palette.BG, Palette.BAD_LINE, Palette.BAD_TEXT, 17f,
    ).apply { setOnClickListener { onClick() } }

    private fun styled(b: Button, label: String, enabled: Boolean, fill: Int, line: Int?, textColor: Int, sizeSp: Float, padV: Int = 14) = b.apply {
        text = label
        isAllCaps = false
        isEnabled = enabled
        stateListAnimator = null
        setTextColor(ColorStateList(arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf()), intArrayOf(Palette.LABEL, textColor)))
        setTextSize(TypedValue.COMPLEX_UNIT_SP, sizeSp)
        setTypeface(typeface, Typeface.BOLD)
        background = StateListDrawable().apply {
            addState(intArrayOf(-android.R.attr.state_enabled), rounded(Palette.SURFACE, 20, Palette.LINE))
            addState(intArrayOf(android.R.attr.state_pressed), rounded(if (fill == Palette.ACCENT) Palette.ACCENT_DARK else Palette.LINE, 20, line, 2))
            addState(intArrayOf(), rounded(fill, 20, line, 2))
        }
        setPadding(dp(16), dp(padV), dp(16), dp(padV))
        minHeight = dp(52)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(10)
    }

    /** A large, high-contrast checkbox with its label. */
    fun checkbox(label: String, onChange: (Boolean) -> Unit) = android.widget.CheckBox(activity).apply {
        text = label
        setTextColor(Palette.TEXT)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 17f)
        buttonTintList = ColorStateList.valueOf(Palette.ACCENT_TEXT)
        setPadding(dp(8), dp(10), 0, dp(10))
        setOnCheckedChangeListener { _, checked -> onChange(checked) }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(12)
    }

    /** A Solana address in groups of 4 characters, so it's easier to compare by eye. */
    fun address(b58: String) = mono(b58.chunked(4).joinToString(" ")).apply { setTextSize(TypedValue.COMPLEX_UNIT_SP, 19f) }

    /**
     * A button that acts only after being held for [holdMs], so a stray tap can't sign anything.
     * Releasing early cancels. A darker band fills it from the left while held.
     */
    fun holdButton(label: String, holdMs: Long = 1500, danger: Boolean = false, onDone: () -> Unit): Button {
        val b = if (danger) dangerButton(label) {} else primaryButton(label) {}
        val fill = ClipDrawable(rounded(if (danger) Palette.BAD_BG else Palette.ACCENT_DARK, 20), Gravity.START, ClipDrawable.HORIZONTAL)
        b.background = LayerDrawable(arrayOf(if (danger) rounded(Palette.BG, 20, Palette.BAD_LINE, 2) else rounded(Palette.ACCENT, 20), fill))
        return b.apply {
            setOnClickListener(null)
            isLongClickable = false
            val tick = 50L
            var held = 0L
            val step = object : Runnable {
                override fun run() {
                    held += tick
                    fill.level = (held * 10_000 / holdMs).toInt().coerceAtMost(10_000)
                    if (held >= holdMs) {
                        text = label
                        fill.level = 0
                        onDone()
                    } else {
                        text = "Keep holding…"
                        postDelayed(this, tick)
                    }
                }
            }
            @Suppress("ClickableViewAccessibility")
            setOnTouchListener { v, e ->
                when (e.actionMasked) {
                    MotionEvent.ACTION_DOWN -> {
                        held = 0
                        v.isPressed = true
                        text = "Keep holding…"
                        postDelayed(step, tick)
                    }
                    MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                        v.isPressed = false
                        removeCallbacks(step)
                        if (held < holdMs) {
                            text = label
                            fill.level = 0
                        }
                    }
                }
                true
            }
        }
    }

    /** A compact key for the word picker's letter keyboard. */
    fun key(label: String, enabled: Boolean = true, onClick: () -> Unit) = button(label, enabled, onClick).apply {
        minWidth = 0
        minimumWidth = 0
        minHeight = dp(48)
        setPadding(dp(2), dp(10), dp(2), dp(10))
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        (layoutParams as LinearLayout.LayoutParams).topMargin = dp(4)
    }

    /** Lays [items] out in rows of [columns] equal-width cells. */
    fun grid(columns: Int, items: List<View>): LinearLayout = LinearLayout(activity).apply {
        orientation = LinearLayout.VERTICAL
        items.chunked(columns).forEach { rowItems ->
            val row = LinearLayout(activity).apply { orientation = LinearLayout.HORIZONTAL }
            rowItems.forEach { row.addView(it, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply { marginEnd = dp(4) }) }
            repeat(columns - rowItems.size) { row.addView(View(activity), LinearLayout.LayoutParams(0, 0, 1f)) }
            addView(row)
        }
    }

    private fun field(e: EditText) = e.apply {
        setTextColor(Palette.TEXT)
        setHintTextColor(Palette.LABEL)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        background = rounded(Palette.SURFACE, 16, Palette.LINE, 2)
        setPadding(dp(16), dp(14), dp(16), dp(14))
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).spaced(10)
    }

    /**
     * Password entry with no suggestions, no keyboard learning and no autofill.
     * Keyboards can still observe input; on an offline vault phone that's an accepted risk for the passphrase,
     * which is why recovery-phrase words never go through the system keyboard at all.
     */
    fun passwordField(hint: String) = sensitive(
        field(EditText(activity)).apply {
            this.hint = hint
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            isSingleLine = true
        },
    )

    /** Plain single-line text entry (names, public addresses): no suggestions, no learning, no autofill. */
    fun textField(hint: String) = field(EditText(activity)).apply {
        this.hint = hint
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING or EditorInfo.IME_FLAG_NO_EXTRACT_UI
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        isSingleLine = true
    }

    /** Hides a view's content from accessibility services that aren't accessibility tools (Android 14+). */
    fun <T : View> sensitive(view: T): T {
        if (Build.VERSION.SDK_INT >= 34) view.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        return view
    }
}
