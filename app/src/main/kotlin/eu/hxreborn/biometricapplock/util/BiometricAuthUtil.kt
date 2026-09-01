package eu.hxreborn.biometricapplock.util

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricManager.Authenticators

const val METHOD_BIOMETRIC = 1
const val METHOD_CREDENTIAL = 1 shl 1
const val METHODS_ALL = METHOD_BIOMETRIC or METHOD_CREDENTIAL

// class floor for METHOD_BIOMETRIC rather than a method of its own
const val METHOD_WEAK_OK = 1 shl 2

const val METHODS_DEFAULT = METHODS_ALL or METHOD_WEAK_OK

enum class BiometricClass { STRONG, WEAK }

enum class BiometricChoice { NONE, STRONGEST, ANY }

// BiometricAuthenticator.TYPE_* values
const val MODALITY_FINGERPRINT = 2
const val MODALITY_FACE = 8

// an empty mask would leave no way to authenticate
fun normalizeMethods(methods: Int): Int =
    if (methods and METHODS_ALL == 0) methods or METHODS_ALL else methods

fun methodAuthenticators(
    method: Int,
    weakOk: Boolean = true,
): Int =
    when (method) {
        // Weak is a floor so Class 3 sensors still qualify
        METHOD_BIOMETRIC -> {
            if (weakOk) Authenticators.BIOMETRIC_WEAK else Authenticators.BIOMETRIC_STRONG
        }

        METHOD_CREDENTIAL -> {
            Authenticators.DEVICE_CREDENTIAL
        }

        else -> {
            0
        }
    }

fun biometricChoice(methods: Int): BiometricChoice =
    when {
        methods and METHOD_BIOMETRIC == 0 -> BiometricChoice.NONE
        methods and METHOD_WEAK_OK != 0 -> BiometricChoice.ANY
        else -> BiometricChoice.STRONGEST
    }

fun choiceAuthenticators(choice: BiometricChoice): Int =
    when (choice) {
        BiometricChoice.NONE -> 0
        BiometricChoice.STRONGEST -> Authenticators.BIOMETRIC_STRONG
        BiometricChoice.ANY -> Authenticators.BIOMETRIC_WEAK
    }

fun withBiometricChoice(
    methods: Int,
    choice: BiometricChoice,
): Int =
    when (choice) {
        // dropping biometrics leaves the screen lock as the only way in
        BiometricChoice.NONE -> {
            (methods or METHOD_CREDENTIAL) and (METHOD_BIOMETRIC or METHOD_WEAK_OK).inv()
        }

        BiometricChoice.STRONGEST -> {
            (methods or METHOD_BIOMETRIC) and METHOD_WEAK_OK.inv()
        }

        BiometricChoice.ANY -> {
            methods or METHOD_BIOMETRIC or METHOD_WEAK_OK
        }
    }

// the last remaining method never turns off
fun withCredential(
    methods: Int,
    allowed: Boolean,
): Int =
    if (allowed || methods and METHOD_BIOMETRIC == 0) {
        methods or METHOD_CREDENTIAL
    } else {
        methods and METHOD_CREDENTIAL.inv()
    }

// one unavailable method never blocks the others
fun usableAuthenticators(
    context: Context,
    bm: BiometricManager,
    methods: Int,
): Int? {
    val weakOk = methods and METHOD_WEAK_OK != 0
    var authenticators = 0
    for (method in intArrayOf(METHOD_BIOMETRIC, METHOD_CREDENTIAL)) {
        if (methods and method == 0) continue
        val requested = methodAuthenticators(method, weakOk)
        if (bm.canAuthenticate(requested) == BiometricManager.BIOMETRIC_SUCCESS) {
            authenticators = authenticators or requested
        } else if (method == METHOD_BIOMETRIC && weakOk && hasFaceHardware(context)) {
            // Standard BiometricPrompt rejects face-only devices (BIOMETRIC_ERROR_NONE_ENROLLED).
            // When we detect a custom OEM face sensor with at least one face enrolled, we must
            // add DEVICE_CREDENTIAL so the system BiometricPrompt can display the PIN/pattern
            // fallback. The MIUI binder path fires in parallel and takes over on success.
            val faceEnrolled =
                miuiFaceEnrollmentCount(context) ?: samsungFaceEnrollmentCount(context) ?: 0
            android.util.Log.d(
                "BiometricAppLock",
                "usableAuthenticators: custom face check enrolled=$faceEnrolled",
            )
            if (faceEnrolled > 0) {
                authenticators =
                    authenticators or requested or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            }
        }
    }
    return authenticators.takeIf { it != 0 }
}

// the OS names the sensors each tier reaches, so two tiers reading alike is the honest answer
fun sensorSettingName(
    context: Context,
    authenticators: Int,
): String? =
    runCatching {
        context
            .getSystemService(BiometricManager::class.java)
            .getStrings(authenticators)
            .settingName
            ?.toString()
    }.getOrNull()?.takeIf { it.isNotBlank() }

// the OS only names a different sensor set for Weak when a Class 2 sensor adds one
fun inferredFaceClass(context: Context): BiometricClass? {
    if (!context.packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) return null
    val strong = sensorSettingName(context, Authenticators.BIOMETRIC_STRONG) ?: return null
    val weak = sensorSettingName(context, Authenticators.BIOMETRIC_WEAK) ?: return null
    return if (strong == weak) BiometricClass.STRONG else BiometricClass.WEAK
}

@Volatile private var sensorClassCache: Map<Int, BiometricClass>? = null

fun sensorClasses(): Map<Int, BiometricClass> =
    sensorClassCache ?: readSensorClasses().also { sensorClassCache = it }

// per-sensor strength sits behind USE_BIOMETRIC_INTERNAL, only the root shell can reach it
private fun readSensorClasses(): Map<Int, BiometricClass> {
    val dump = RootShell.exec("dumpsys biometric").out.joinToString("\n")

    val aosp =
        Regex("""updatedStrength:\s*(\d+), modality (\d+)""")
            .findAll(dump)
            .mapNotNull { match ->
                val strength = match.groupValues[1].toIntOrNull() ?: return@mapNotNull null
                val modality = match.groupValues[2].toIntOrNull() ?: return@mapNotNull null
                when {
                    strength <= Authenticators.BIOMETRIC_STRONG -> modality to BiometricClass.STRONG
                    strength <= Authenticators.BIOMETRIC_WEAK -> modality to BiometricClass.WEAK
                    else -> null
                }
            }

    val samsung =
        if (!android.os.Build.MANUFACTURER
                .equals("samsung", ignoreCase = true)
        ) {
            emptySequence()
        } else {
            // One UI dumpsys biometric uses {strength, modality} pairs — strength comes first.
            // The regex is intentionally Samsung-only to avoid false positives on other OEMs.
            Regex("""\{(\d+),\s*(\d+)\}""")
                .findAll(dump)
                .mapNotNull { match ->
                    val strength = match.groupValues[1].toIntOrNull() ?: return@mapNotNull null
                    val modality = match.groupValues[2].toIntOrNull() ?: return@mapNotNull null
                    when {
                        strength <= Authenticators.BIOMETRIC_STRONG -> {
                            modality to
                                BiometricClass.STRONG
                        }

                        strength <= Authenticators.BIOMETRIC_WEAK -> {
                            modality to BiometricClass.WEAK
                        }

                        else -> {
                            null
                        }
                    }
                }
        }

    return (samsung + aosp).toMap()
}

fun hasFaceHardware(context: Context): Boolean =
    context.packageManager.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FACE) ||
        samsungFaceEnrollmentCount(context) != null ||
        hasMiuiFace(context)

fun samsungFaceEnrollmentCount(context: Context): Int? {
    if (!android.os.Build.MANUFACTURER
            .equals("samsung", ignoreCase = true)
    ) {
        return null
    }
    val faceScreenLock =
        android.provider.Settings.Secure.getInt(
            context.contentResolver,
            "face_screen_lock",
            -1,
        )
    return when (faceScreenLock) {
        1 -> 1
        0 -> 0
        else -> null
    }
}

// MIUI/HyperOS devices keep face unlock in a separate service (miui.face.FaceService).
// Cached to avoid repeated IPC on every showPrompt call.
// Call invalidateMiuiFaceEnrollmentCache() after any enrollment change (e.g. if you observe
// Settings.Secure changes for "face_unlock_valid_feature").
@Volatile private var miuiFaceEnrollmentCache: Int = Int.MIN_VALUE

fun invalidateMiuiFaceEnrollmentCache() {
    miuiFaceEnrollmentCache = Int.MIN_VALUE
}

fun miuiFaceEnrollmentCount(context: Context): Int? {
    if (miuiFaceEnrollmentCache != Int.MIN_VALUE) {
        return if (miuiFaceEnrollmentCache < 0) null else miuiFaceEnrollmentCache
    }
    val result = checkMiuiFaceEnrollment(context)
    miuiFaceEnrollmentCache = result ?: -1
    return result
}

private fun checkMiuiFaceEnrollment(context: Context): Int? {
    // Covers both Xiaomi and POCO devices (POCO is a Xiaomi sub-brand)
    if (!android.os.Build.MANUFACTURER
            .equals("xiaomi", ignoreCase = true) &&
        !android.os.Build.MANUFACTURER
            .equals("poco", ignoreCase = true)
    ) {
        return null
    }

    return try {
        // face_unlock_valid_feature = 1 means a face is enrolled in HyperOS / MIUI.
        // We read this directly; no ServiceManager pre-check needed since non-Xiaomi devices
        // simply won't have the key (returns the default -1).
        val settingValue =
            android.provider.Settings.Secure.getInt(
                context.contentResolver,
                "face_unlock_valid_feature",
                -1,
            )
        when (settingValue) {
            1 -> 1

            // face enrolled
            0 -> 0

            // service present but nothing enrolled
            else -> 0 // key absent — treat as not enrolled
        }
    } catch (e: Exception) {
        0
    }
}

// hasMiuiFace is true only when confirmed face hardware AND at least one face enrolled (count >= 1).
// count == 0 means the service exists but nothing is enrolled — do not show the face hardware card.
fun hasMiuiFace(context: Context): Boolean = (miuiFaceEnrollmentCount(context) ?: -1) >= 1
