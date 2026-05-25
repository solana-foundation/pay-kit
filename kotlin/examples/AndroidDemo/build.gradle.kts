// Root project for the MPP Android demo. AGP and Kotlin plugins are
// declared here with apply false so the :app module can resolve them
// without duplicating versions.
plugins {
    id("com.android.application") version "8.5.2" apply false
    kotlin("android") version "1.9.25" apply false
}
