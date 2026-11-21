import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    implementation(project(":core"))
    // QR encoding and decoding. Dependency-free (its JUnit dependency is test-scoped), Apache-2.0.
    // Only the core library: no zxing "android" or "javase" helpers.
    implementation("com.google.zxing:core:3.5.4")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
    testImplementation("org.json:json:20240303")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("isol8.vectors", rootProject.projectDir.resolve("../protocol/vectors").canonicalPath)
    testLogging {
        events("failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// Development tool: an HTML page of test QR codes to scan with the vault on a test device.
tasks.register<JavaExec>("testPage") {
    group = "verification"
    description = "Writes build/test-page/index.html with test QR codes (protocol vectors only)."
    classpath = sourceSets["test"].runtimeClasspath
    mainClass.set("app.isol8.vault.qr.TestPageKt")
    args(
        rootProject.projectDir.resolve("../protocol/vectors").canonicalPath,
        layout.buildDirectory.file("test-page/index.html").get().asFile.path,
        layout.buildDirectory.file("test-page/device-requests.json").get().asFile.path,
    )
}
