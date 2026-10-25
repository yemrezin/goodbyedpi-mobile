plugins {
    id("com.android.application")
}

android {
    namespace = "com.goodbyedpi.turkey"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.goodbyedpi.turkey"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.2.3rc3-turkey"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
