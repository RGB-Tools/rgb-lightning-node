import org.gradle.api.publish.maven.MavenPublication
import java.net.URI

plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "1.9.24"
    id("maven-publish")
    id("org.jreleaser") version "1.19.0"
}

group = providers.gradleProperty("GROUP_ID").orElse("org.utexo").get()
version = providers.gradleProperty("VERSION_NAME").orElse("0.0.0-dev").get()

val generatedBindingsDir = layout.projectDirectory.dir("../../target/uniffi/kotlin-android")
val generatedJniDir = layout.projectDirectory.dir("../../target/uniffi/kotlin-android/jniLibs")

android {
    namespace = "org.utexo.rgblightningnode"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    sourceSets {
        getByName("main") {
            java.srcDir(generatedBindingsDir)
            jniLibs.srcDir(generatedJniDir)
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = providers.gradleProperty("GROUP_ID").orElse(group.toString()).get()
                artifactId = providers.gradleProperty("ARTIFACT_ID").orElse("rgb-lightning-node-android").get()
                version = providers.gradleProperty("VERSION_NAME").orElse(version.toString()).get()

                pom {
                    name.set("RGB Lightning Node Android SDK")
                    description.set("Android Kotlin bindings and JNI artifacts for RGB Lightning Node")
                    url.set("https://github.com/UTEXO-Protocol/rgb-lightning-node")
                    licenses {
                        license {
                            name.set("MIT")
                            url.set("https://opensource.org/licenses/MIT")
                        }
                    }
                    developers {
                        developer {
                            id.set("utexo")
                            name.set("UTEXO")
                        }
                    }
                    scm {
                        connection.set("scm:git:git://github.com/UTEXO-Protocol/rgb-lightning-node.git")
                        developerConnection.set("scm:git:ssh://git@github.com/UTEXO-Protocol/rgb-lightning-node.git")
                        url.set("https://github.com/UTEXO-Protocol/rgb-lightning-node")
                    }
                }
            }
        }

        repositories {
            maven {
                name = "stagingDeploy"
                // JReleaser consumes this local staged repository and handles signing/upload.
                url = URI(layout.buildDirectory.dir("staging-deploy").get().asFile.toURI().toString())
            }
        }
    }
}

jreleaser {
    project {
        name.set("rgb-lightning-node-kotlin-android")
        description.set("RGB Lightning Node Kotlin Android bindings")
        longDescription.set("Kotlin Android bindings and JNI artifacts for RGB Lightning Node")
        website.set("https://github.com/UTEXO-Protocol/rgb-lightning-node")
        authors.set(listOf("UTEXO"))
        license.set("MIT")
        licenseUrl.set("https://spdx.org/licenses/MIT.html")

        java {
            groupId.set(providers.gradleProperty("GROUP_ID").orElse("org.utexo"))
            version.set("17")
        }
    }

    release {
        github {
            // Keep enabled to satisfy JReleaser core requirements.
            enabled.set(true)
        }
    }

    signing {
        active.set(org.jreleaser.model.Active.ALWAYS)
        armored.set(true)
        mode.set(org.jreleaser.model.Signing.Mode.COMMAND)

        command {
            keyName.set(providers.gradleProperty("jreleaser.gpg.keyName"))
            passphrase.set(providers.gradleProperty("jreleaser.gpg.passphrase"))
        }
    }

    deploy {
        maven {
            pomchecker {
                failOnError.set(false)
                failOnWarning.set(false)
            }

            mavenCentral {
                create("sonatype") {
                    active.set(org.jreleaser.model.Active.ALWAYS)
                    url.set("https://central.sonatype.com/api/v1/publisher")
                    stagingRepository("build/staging-deploy")
                    verifyPom.set(false)
                }
            }
        }
    }
}
