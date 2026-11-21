package app.isol8.vault

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CameraMetadata
import android.hardware.camera2.CaptureRequest
import android.hardware.camera2.params.OutputConfiguration
import android.hardware.camera2.params.SessionConfiguration
import android.media.ImageReader
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.util.Size
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import app.isol8.vault.qr.QrScanner
import java.util.concurrent.Executor
import kotlin.math.abs

/**
 * A live camera preview that reports isol8 QR frames, using Android's own Camera2 API (no AndroidX).
 * Frames are analysed in memory and never saved. [onText] and [onError] run on the main thread,
 * never after [stop].
 */
class QrCamera(
    private val activity: Activity,
    private val onText: (String) -> Unit,
    private val onError: (String) -> Unit,
    /** Development builds only: a once-a-second line about what the decoder sees. */
    private val onDebug: ((String) -> Unit)? = null,
    /** True: only isol8 frames. False: any QR text (a wallet's receive code, for the address book). */
    private val isol8Only: Boolean = true,
) {
    private val manager = activity.getSystemService(CameraManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val thread = HandlerThread("isol8-camera").apply { start() }
    private val handler = Handler(thread.looper)
    /** After [stop] the thread is gone; late camera callbacks then run inline so they can still close the device. */
    private val executor = Executor { r -> if (!handler.post(r)) r.run() }

    private val cameraId: String?
    private val analysisSize: Size
    private val sensorOrientation: Int

    // Touched only on the camera thread after start().
    private var device: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private val scanner = QrScanner()
    private var luminance = ByteArray(0)
    private var lastText: String? = null
    private var analysed = 0
    private var lastDebug = 0L

    @Volatile private var stopped = false
    private var opened = false

    val view: SurfaceView

    init {
        cameraId = pickCamera()
        val chars = cameraId?.let { manager.getCameraCharacteristics(it) }
        sensorOrientation = chars?.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
        analysisSize = chars?.let { pickSize(it) } ?: Size(1280, 720)
        view = PreviewView()
        view.holder.setFixedSize(analysisSize.width, analysisSize.height)
        view.holder.addCallback(object : SurfaceHolder.Callback {
            override fun surfaceCreated(holder: SurfaceHolder) = Unit
            override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
                if (width == analysisSize.width && height == analysisSize.height) open()
            }
            override fun surfaceDestroyed(holder: SurfaceHolder) = stop()
        })
    }

    /** Stops the camera and its thread. Safe to call more than once. */
    fun stop() {
        if (stopped) return
        stopped = true
        handler.post {
            try {
                session?.close()
                device?.close()
                reader?.close()
            } catch (e: RuntimeException) {
                // Closing a camera that already failed can throw; nothing else to do.
            }
            session = null
            device = null
            reader = null
            luminance.fill(0)
        }
        thread.quitSafely()
    }

    private fun pickCamera(): String? {
        val ids = manager.cameraIdList
        return ids.firstOrNull { manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) == CameraMetadata.LENS_FACING_BACK }
            ?: ids.firstOrNull()
    }

    /** A YUV size near 1280×720 that the preview surface also supports: big enough for a version 12 QR code. */
    private fun pickSize(chars: CameraCharacteristics): Size {
        val map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP) ?: return Size(1280, 720)
        val preview = map.getOutputSizes(SurfaceHolder::class.java).orEmpty().toSet()
        val candidates = map.getOutputSizes(ImageFormat.YUV_420_888).orEmpty()
            .filter { it in preview && it.width * it.height <= 1920 * 1080 }
        return candidates.minByOrNull { abs(it.width * it.height - 1280 * 720) } ?: Size(1280, 720)
    }

    private fun open() {
        if (opened || stopped) return
        opened = true
        val id = cameraId ?: return fail("This device has no camera.")
        if (activity.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            return fail("Camera permission is off.")
        }
        val surface = view.holder.surface
        try {
            manager.openCamera(id, executor, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    if (stopped) return camera.close()
                    device = camera
                    startSession(camera, surface)
                }
                override fun onDisconnected(camera: CameraDevice) {
                    camera.close()
                    fail("The camera was disconnected.")
                }
                override fun onError(camera: CameraDevice, error: Int) {
                    camera.close()
                    fail("The camera reported error $error.")
                }
            })
        } catch (e: Exception) {
            fail("Couldn't open the camera: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    private fun startSession(camera: CameraDevice, preview: Surface) {
        val r = ImageReader.newInstance(analysisSize.width, analysisSize.height, ImageFormat.YUV_420_888, 2)
        reader = r
        r.setOnImageAvailableListener({ analyse(it) }, handler)
        val outputs = listOf(OutputConfiguration(preview), OutputConfiguration(r.surface))
        val config = SessionConfiguration(SessionConfiguration.SESSION_REGULAR, outputs, executor, object : CameraCaptureSession.StateCallback() {
            override fun onConfigured(s: CameraCaptureSession) {
                if (stopped) return s.close()
                session = s
                val request = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                    addTarget(preview)
                    addTarget(r.surface)
                    set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                }
                try {
                    s.setRepeatingRequest(request.build(), null, handler)
                } catch (e: Exception) {
                    fail("Couldn't start the camera: ${e.message ?: e.javaClass.simpleName}")
                }
            }
            override fun onConfigureFailed(s: CameraCaptureSession) = fail("Couldn't configure the camera.")
        })
        try {
            camera.createCaptureSession(config)
        } catch (e: Exception) {
            fail("Couldn't start the camera: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    /** Runs on the camera thread. Copies the luminance plane, releases the image, then decodes. */
    private fun analyse(r: ImageReader) {
        val image = r.acquireLatestImage() ?: return
        val width: Int
        val height: Int
        val stride: Int
        try {
            if (stopped) return
            val plane = image.planes[0] // Y plane: pixel stride is always 1 for YUV_420_888
            width = image.width
            height = image.height
            stride = plane.rowStride
            val buffer = plane.buffer
            if (luminance.size < stride * height) luminance = ByteArray(stride * height)
            buffer.get(luminance, 0, minOf(buffer.remaining(), luminance.size))
        } finally {
            image.close()
        }
        val text = if (isol8Only) scanner.scanLuminance(luminance, stride, width, height) else scanner.scanAnyLuminance(luminance, stride, width, height)
        analysed++
        onDebug?.let { debug ->
            val now = android.os.SystemClock.elapsedRealtime()
            if (now - lastDebug >= 1000) {
                lastDebug = now
                val line = "Debug: $analysed frames, ${width}×$height (stride $stride), last: ${if (text != null) "QR text read" else scanner.lastMiss}"
                main.post { if (!stopped) debug(line) }
            }
        }
        if (text == null) return
        if (text == lastText) return
        lastText = text
        main.post { if (!stopped) onText(text) }
    }

    private fun fail(message: String) {
        main.post { if (!stopped) onError(message) }
    }

    /** Keeps the preview's aspect ratio, rotated to how the camera image appears on screen. */
    private inner class PreviewView : SurfaceView(activity) {
        override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
            val width = View.MeasureSpec.getSize(widthMeasureSpec)
            val rotation = if (Build.VERSION.SDK_INT >= 30) activity.display?.rotation ?: 0 else {
                @Suppress("DEPRECATION")
                activity.windowManager.defaultDisplay.rotation
            }
            val displayDegrees = rotation * 90
            val sideways = (sensorOrientation + displayDegrees) % 180 != 0
            val ratio = if (sideways) analysisSize.width.toFloat() / analysisSize.height else analysisSize.height.toFloat() / analysisSize.width
            // Leave room for instructions below on short (landscape) screens.
            val maxHeight = (resources.displayMetrics.heightPixels * 0.55f).toInt()
            var w = width
            var h = (w * ratio).toInt()
            if (h > maxHeight) {
                h = maxHeight
                w = (h / ratio).toInt()
            }
            setMeasuredDimension(w, h)
        }
    }
}
