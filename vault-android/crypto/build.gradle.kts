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
    // The vault's only third-party runtime library. Used through its low-level ("lightweight") API,
    // never registered as a JCA provider, so it can't clash with Android's internal copy.
    implementation("org.bouncycastle:bcprov-jdk18on:1.80")

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
