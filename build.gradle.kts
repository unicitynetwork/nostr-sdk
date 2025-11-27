plugins {
    java
    `maven-publish`
    id("ru.vyarus.animalsniffer") version "2.0.1"
}

group = "org.unicitylabs"
// Use version property if provided, otherwise use default
version = if (project.hasProperty("version")) {
    project.property("version").toString()
} else {
    "1.0-SNAPSHOT"
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
    withJavadocJar()
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

    // Animal Sniffer signature for Android API 31
    // Ensures we only use Java 11 APIs compatible with Android
    signature("com.toasttab.android:gummy-bears-api-31:0.11.0@signature")

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

// Animal Sniffer configuration
animalsniffer {
    // Animal Sniffer is configured via the signature dependency above
}

tasks.test {
    useJUnit()
    // Exclude E2E tests from normal build - they require manual interaction
    exclude("**/*E2ETest*")
}

// Separate task to run E2E tests explicitly
tasks.register<Test>("e2eTest") {
    useJUnit()
    include("**/*E2ETest*")
}

// Publishing configuration for JitPack
publishing {
    publications {
        create<MavenPublication>("maven") {
            groupId = project.group.toString()
            artifactId = "nostr-sdk"
            version = project.version.toString()

            from(components["java"])

            pom {
                name.set("Unicity Nostr SDK")
                description.set("Java SDK for Nostr protocol integration with Unicity blockchain")
                url.set("https://github.com/unicitynetwork/nostr-sdk")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("unicitynetwork")
                        name.set("Unicity Labs")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/unicitynetwork/nostr-sdk.git")
                    developerConnection.set("scm:git:ssh://github.com/unicitynetwork/nostr-sdk.git")
                    url.set("https://github.com/unicitynetwork/nostr-sdk")
                }
            }
        }
    }
}
