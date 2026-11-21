rootProject.name = "isol8-vault"

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        // Google's repository only for Android build tooling (AGP pulls aapt2 from here at build time).
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google\\.android.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
    }
}

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        gradlePluginPortal()
        mavenCentral()
    }
}

// core: pure Kotlin protocol core (JDK only).
// crypto: key handling that needs a library (BouncyCastle: Ed25519, later Argon2id). JVM-testable.
// qr: QR encoding and decoding of isol8 frames (ZXing core). JVM-testable.
// app: the Android vault app.
include(":core", ":crypto", ":qr", ":app")
