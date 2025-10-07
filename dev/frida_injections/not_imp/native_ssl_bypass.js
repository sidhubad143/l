/*
Protective Source License v1.0 (PSL-1.0)
Copyright (c) 2025 Kaif
Unauthorized removal of credits or use for abusive/illegal purposes
will terminate all rights granted under this license.
*/



'use strict';

function logger(message) {
    console.log(message);
    Java.perform(() => {
        const Log = Java.use("android.util.Log");
        Log.v("SSL_PINNING_BYPASS", message);
    });
}

// Hook native SSL verification function (libstartup.so example)
function hookNativeSSLVerification(libName, funcNameContains) {
    const module = Process.findModuleByName(libName);
    if (!module) {
        logger(`[*][-] Module ${libName} not found, waiting...`);
        // Wait for module to load
        const interval = setInterval(() => {
            const mod = Process.findModuleByName(libName);
            if (mod) {
                clearInterval(interval);
                hookNativeSSLVerification(libName, funcNameContains);
            }
        }, 300);
        return;
    }

    const exports = module.enumerateExports();
    const targetFunc = exports.find(e => e.name.includes(funcNameContains));
    if (!targetFunc) {
        logger(`[*][-] Function containing "${funcNameContains}" not found in ${libName}`);
        return;
    }

    try {
        Interceptor.attach(targetFunc.address, {
            onLeave: function (retval) {
                retval.replace(1);  // force success
                logger(`[*][+] Native SSL verification hooked: ${targetFunc.name}`);
            }
        });
    } catch (e) {
        logger(`[*][-] Failed to hook native SSL verification: ${e}`);
    }
}

Java.perform(() => {
    // Native hook (adjust lib and function name if needed)
    hookNativeSSLVerification("libstartup.so", "verifyWithMetrics");

    try {
        const ArrayList = Java.use("java.util.ArrayList");

        // Hook checkTrustedRecursive if present (some Android versions)
        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        if (TrustManagerImpl.checkTrustedRecursive) {
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                logger("[*][+] Hooked checkTrustedRecursive - bypassing trust checks");
                return ArrayList.$new();
            };
        } else {
            logger("[*][-] checkTrustedRecursive not found, skipping");
        }
    } catch (e) {
        logger(`[*][-] Error hooking checkTrustedRecursive: ${e}`);
    }

    try {
        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        const SSLContext = Java.use("javax.net.ssl.SSLContext");

        // Create a TrustManager that trusts everything
        const TrustManager = Java.registerClass({
            name: "org.bypass.TrustManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted(chain, authType) {},
                checkServerTrusted(chain, authType) {},
                getAcceptedIssuers() { return []; }
            }
        });

        const trustManagers = [TrustManager.$new()];

        // Hook SSLContext.init() to replace trust managers with our bypass one
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (keyManager, trustManager, secureRandom) {
            logger("[*][+] Hooked SSLContext.init - injecting bypass TrustManager");
            return this.init(keyManager, trustManagers, secureRandom);
        };
    } catch (e) {
        logger(`[*][-] Error hooking SSLContext.init: ${e}`);
    }
});
