import com.android.build.api.artifact.SingleArtifact
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "app.isol8.vault"
    compileSdk = 36
    // Pinned: otherwise AGP picks its own default (35.0.0) and downloads it during the build if missing.
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "app.isol8.vault"
        minSdk = 29 // Android 10: spare phones are often old
        targetSdk = 36 // Android 16
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        release {
            // Release builds and signing happen in the release qube, never here (release/README.md).
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // No BuildConfig, no AIDL, no RenderScript: less generated code.
    buildFeatures {
        buildConfig = false
        aidl = false
        resValues = false
        shaders = false
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        // Release builds skip lint (lintVital): its tools are a large set of extra build dependencies, and the release
        // build should pull as little as possible. Lint stays a dev-qube check.
        checkReleaseBuilds = false
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Deliberately no AndroidX: every dependency is attack surface in the vault.
    // Third-party runtime libraries: BouncyCastle and ZXing core only.
    implementation(project(":core"))
    implementation(project(":crypto")) // brings BouncyCastle
    implementation(project(":qr")) // brings ZXing core, for QR encoding and decoding
}

// ---------------------------------------------------------------------------------------------
// Enforcement checks (docs/SECURITY.md, "The vault phone, in layers": layers 3 and 4). They run before every assemble.
// ---------------------------------------------------------------------------------------------

/**
 * The only permissions the vault may request. Adding one is a security decision: review it like code.
 * Anything that grants network access (INTERNET, CHANGE_NETWORK_STATE, ...) must never be added.
 */
val allowedPermissions: Set<String> = setOf(
    // Scanning QR codes from the dashboard (milestone 3). Frames are decoded in memory, never saved.
    "android.permission.CAMERA",
)
val neverAllowed = setOf(
    "android.permission.INTERNET",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.NFC",
    "android.permission.QUERY_ALL_PACKAGES",
)

/**
 * Strings that must not appear in our compiled classes (constant pool): APIs that reach the network,
 * open links, launch or talk to other apps, or put data where other apps can read it.
 * This scans our own code (app, core, crypto, qr). Library code (BouncyCastle, ZXing, the Kotlin standard library)
 * is covered later by an APK-level scan after R8.
 */
val forbiddenReferences = listOf(
    "java/net/", "javax/net/", "android/net/http", "android/webkit/",
    "android/net/Uri",
    "startActivity", "startService", "startForegroundService", "bindService", "sendBroadcast",
    "PendingIntent", "createChooser", "ACTION_VIEW", "ACTION_SEND",
    "android/content/ClipboardManager", "android/content/ClipData",
    "android/app/DownloadManager", "android/print/",
)

androidComponents {
    onVariants { variant ->
        val cap = variant.name.replaceFirstChar { it.uppercase() }

        val verifyPermissions = tasks.register("verify${cap}Permissions") {
            group = "verification"
            description = "Fails if the merged ${variant.name} manifest requests any permission outside the allowlist."
            val manifest = variant.artifacts.get(SingleArtifact.MERGED_MANIFEST)
            inputs.file(manifest)
            val allowed = allowedPermissions
            val banned = neverAllowed
            doLast {
                val doc = javax.xml.parsers.DocumentBuilderFactory.newInstance()
                    .apply { isNamespaceAware = true }
                    .newDocumentBuilder().parse(manifest.get().asFile)
                val androidNs = "http://schemas.android.com/apk/res/android"
                val requested = buildList {
                    for (tag in listOf("uses-permission", "uses-permission-sdk-23")) {
                        val nodes = doc.getElementsByTagName(tag)
                        for (i in 0 until nodes.length) add((nodes.item(i) as org.w3c.dom.Element).getAttributeNS(androidNs, "name"))
                    }
                }
                val forbidden = requested.filter { it in banned }
                val unexpected = requested.filter { it !in allowed }
                if (forbidden.isNotEmpty() || unexpected.isNotEmpty()) {
                    throw GradleException(
                        "Vault manifest (${variant.name}) requests permissions it must not have.\n" +
                            (if (forbidden.isNotEmpty()) "  Never allowed: $forbidden\n" else "") +
                            "  Not in the allowlist: $unexpected\n" +
                            "  If one came from a library's manifest, remove the library or strip the permission with tools:node=\"remove\".",
                    )
                }
                logger.lifecycle("verify${cap}Permissions: OK (requested: ${requested.ifEmpty { listOf("none") }})")
            }
        }

        val verifyApis = tasks.register("verify${cap}ForbiddenApis") {
            group = "verification"
            description = "Fails if our compiled ${variant.name} classes reference network, link, app-launch or clipboard APIs."
            val classDirs = files(
                layout.buildDirectory.dir("tmp/kotlin-classes/${variant.name}"),
                project(":core").layout.buildDirectory.dir("classes/kotlin/main"),
                project(":crypto").layout.buildDirectory.dir("classes/kotlin/main"),
                project(":qr").layout.buildDirectory.dir("classes/kotlin/main"),
            )
            dependsOn("compile${cap}Kotlin", ":core:compileKotlin", ":crypto:compileKotlin", ":qr:compileKotlin")
            inputs.files(classDirs)
            val forbidden = forbiddenReferences
            doLast {
                val hits = mutableListOf<String>()
                var scanned = 0
                classDirs.asFileTree.matching { include("**/*.class") }.forEach { f ->
                    scanned++
                    val text = String(f.readBytes(), Charsets.ISO_8859_1)
                    forbidden.filter { text.contains(it) }.forEach { hits += "${f.name}: $it" }
                }
                if (scanned == 0) throw GradleException("verify${cap}ForbiddenApis: no classes found to scan; the check is misconfigured")
                if (hits.isNotEmpty()) throw GradleException("Forbidden API references in vault code:\n  " + hits.joinToString("\n  "))
                logger.lifecycle("verify${cap}ForbiddenApis: OK ($scanned classes scanned)")
            }
        }

        // Hooked to packaging itself, so no APK can be produced (by assemble, install or anything else)
        // without passing both checks.
        tasks.matching { it.name == "package$cap" || it.name == "check" }.configureEach {
            dependsOn(verifyPermissions, verifyApis)
        }
    }
}
