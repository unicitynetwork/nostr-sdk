plugins {
    java
    `maven-publish`
}

group = "org.unicitylabs"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11

    // Use Java 17 for compilation, but target Java 11 bytecode
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // JSON serialization
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.0")
    implementation("com.fasterxml.jackson.core:jackson-core:2.17.0")
    implementation("com.fasterxml.jackson.core:jackson-annotations:2.17.0")

    // WebSocket communication
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Cryptography (BouncyCastle for pure Java crypto)
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")

    // Phone number normalization for nametag hashing
    implementation("com.googlecode.libphonenumber:libphonenumber:8.13.51")

    // Hex encoding utilities
    implementation("commons-codec:commons-codec:1.16.0")

    // Logging facade
    implementation("org.slf4j:slf4j-api:2.0.9")

    // Testing
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.awaitility:awaitility:4.2.0")
    testImplementation("org.mockito:mockito-core:5.10.0")
    testImplementation("ch.qos.logback:logback-classic:1.4.11")
}

tasks.withType<JavaCompile> {
    options.release.set(11) // Ensure Java 11 bytecode
    options.encoding = "UTF-8"
}

tasks.test {
    useJUnit()
}

// Publishing configuration (for Maven/JitPack)
publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            pom {
                name.set("Unicity Nostr SDK")
                description.set("Java SDK for Nostr protocol integration with Unicity blockchain")
                url.set("https://github.com/unicitynetwork/unicity-nostr-sdk")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
            }
        }
    }
}
