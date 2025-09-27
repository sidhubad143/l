// watch_platform_register_info_safe.js
'use strict';

/*
 Robust watcher for platform_register_info:
 - Works in gadget and frida-il2cpp-bridge environments
 - Observes ctor, captures instance pointer, waits for platform_register_info to be filled
 - Dumps hex to console, sends base64 to host, and attempts to save to /sdcard
*/

const TARGET_ASM = "Assembly-CSharp";
const TARGET_CLASS = "proto.PlatformRegisterReq";
const FIELD_NAME = "platform_register_info";
const POLL_INTERVAL_MS = 300;      // how often to poll the instance for the field
const SAVE_TO_SDCARD = true;      // attempt to write to /sdcard/<ts>_platform_register_info.bin

// safe wrapper around Il2Cpp.perform when available
function safeIl2Cpp(cb) {
    try {
        if (Il2Cpp && typeof Il2Cpp.perform === 'function') {
            return Il2Cpp.perform(cb);
        }
    } catch (e) {
        // fallthrough and try direct
    }
    try { return cb(); } catch (ee) { console.warn("[!] safeIl2Cpp fallback error:", ee); }
}

// helpers: convert managed byte[] to Uint8Array
function managedToUint8(raw) {
    if (!raw) return null;
    try {
        // variant 1: has arrayLength and readByteArray (some bridge builds)
        if (typeof raw.arrayLength === 'number' && typeof raw.readByteArray === 'function') {
            const len = raw.arrayLength;
            const buf = raw.readByteArray(len);
            return new Uint8Array(buf);
        }
    } catch (e) {}
    try {
        // variant 2: has length and get(i)
        if (typeof raw.length === 'number' && typeof raw.get === 'function') {
            const len = raw.length;
            const out = new Uint8Array(len);
            for (let i = 0; i < len; i++) out[i] = raw.get(i) & 0xff;
            return out;
        }
    } catch (e) {}
    try {
        // variant 3: ArrayBuffer-like
        if (raw.byteLength) return new Uint8Array(raw);
    } catch (e) {}
    return null;
}

function u8ToHex(u8) {
    return Array.prototype.map.call(u8, b => b.toString(16).padStart(2, '0')).join(' ');
}
function u8ToB64(u8) {
    try {
        const bin = Array.prototype.map.call(u8, v => String.fromCharCode(v)).join('');
        return btoa(bin);
    } catch (e) { return null; }
}

// write to /sdcard if Java is available
function writeToSdcard(filename, u8arr) {
    try {
        if (!SAVE_TO_SDCARD) return false;
        if (!(typeof Java !== 'undefined' && Java && Java.available)) {
            // try Java.perform later from safeIl2Cpp (host environment might not have Java)
            if (Java && typeof Java.perform === 'function') {
                // fall through to Java.perform block below
            } else {
                return false;
            }
        }
    } catch (e) {}

    try {
        return Java.perform(() => {
            try {
                const File = Java.use("java.io.File");
                const FileOutputStream = Java.use("java.io.FileOutputStream");
                const path = "/sdcard/" + filename;
                const f = File.$new(path);
                const fos = FileOutputStream.$new(f);
                const jarr = Java.array('byte', Array.from(u8arr));
                fos.write(jarr);
                fos.close();
                console.log("[+] wrote file to", path);
                return true;
            } catch (e) {
                console.warn("[!] writeToSdcard failure:", e);
                return false;
            }
        });
    } catch (e) {
        // Java not available
        return false;
    }
}

// safe send to host (catch errors if using gadget CLI)
function safeSend(payload) {
    try { send(payload); } catch (e) { /* ignore */ }
}

// main
safeIl2Cpp(() => {
    // try multiple names for assemblies / domain API to be robust
    let asm = null;
    try {
        asm = (Il2Cpp.Domain && Il2Cpp.Domain.assembly) ? Il2Cpp.Domain.assembly(TARGET_ASM) : (Il2Cpp.domain ? Il2Cpp.domain.assembly(TARGET_ASM) : null);
    } catch (e) {
        try { asm = Il2Cpp.domain.assembly(TARGET_ASM); } catch (ee) { asm = null; }
    }

    if (!asm) {
        console.error("[-] Assembly not found yet. Polling for assembly...");
    }

    // poll until class exists
    const pollAsm = setInterval(() => {
        try {
            // get assembly reference each tick (fresh)
            try {
                asm = (Il2Cpp.Domain && Il2Cpp.Domain.assembly) ? Il2Cpp.Domain.assembly(TARGET_ASM) : (Il2Cpp.domain ? Il2Cpp.domain.assembly(TARGET_ASM) : null);
            } catch (e) {
                try { asm = Il2Cpp.domain.assembly(TARGET_ASM); } catch (ee) { asm = null; }
            }
            if (!asm) return;

            let img = asm.image;
            if (!img) return;

            // tryClass and class fallbacks
            let klass = null;
            try { klass = img.tryClass(TARGET_CLASS); } catch (e) {}
            if (!klass) {
                try { klass = img.class(TARGET_CLASS); } catch (e) {}
            }
            if (!klass) {
                try { klass = img.tryClass("PlatformRegisterReq"); } catch (e) {}
            }
            if (!klass) return;

            clearInterval(pollAsm);
            console.log("[+] Found class", klass.name, "in", asm.name);

            // find constructor method using methods array safely
            let ctorMethod = null;
            try { ctorMethod = klass.methods.find(m => m.name === ".ctor" || m.name.indexOf(".ctor") !== -1); } catch (e) {}
            if (!ctorMethod) {
                console.warn("[-] No ctor found; falling back to hooking any method that looks like merge/parse.");
            }

            // choose attach target: prefer ctor if available
            let attachTargets = [];
            if (ctorMethod) attachTargets.push(ctorMethod);
            else {
                // fallback: attach to candidate methods that might cause the field to be filled
                const keywords = ["mergefrom","parsefrom","deserialize","serialize","write","tobyte","tobytes","toarray"];
                try {
                    klass.methods.forEach(m => {
                        const nm = (m.name || "").toLowerCase();
                        for (let kw of keywords) { if (nm.indexOf(kw) !== -1) { attachTargets.push(m); break; } }
                    });
                } catch (e) {}
            }

            if (attachTargets.length === 0) {
                console.error("[-] No attach targets found on class. Listing methods for manual inspection:");
                try { klass.methods.slice(0,50).forEach(m => console.log("   -", m.name)); } catch(e){}
                return;
            }

            // attach to each target (but will only act on the instance pointer once)
            attachTargets.forEach(method => {
                try {
                    const addr = method.virtualAddress ? ptr(method.virtualAddress) : (method.handle ? ptr(method.handle) : null);
                    if (!addr) {
                        console.warn("[!] method", method.name, "has no address to attach to.");
                        return;
                    }

                    console.log("[*] Attaching to", method.name, "at", addr);

                    Interceptor.attach(addr, {
                        onEnter: function(args) {
                            // capture instance pointer (x0 / r0)
                            this.instancePtr = args[0];
                        },
                        onLeave: function(retval) {
                            const instPtr = this.instancePtr;
                            if (!instPtr || instPtr.isNull && instPtr.isNull()) return;

                            // now poll this instance until the field is non-null or a short timeout
                            let tries = 0;
                            const maxTries = 40; // ~40 * POLL_INTERVAL_MS before stop (~12s if 300ms)
                            const instHandle = instPtr.toString();
                            const checkInterval = setInterval(() => {
                                tries++;
                                safeIl2Cpp(() => {
                                    try {
                                        const instance = new Il2Cpp.Object(instPtr);
                                        // try to get the field descriptor; fallback to searching for a byte[] field
                                        let fdesc = null;
                                        try { fdesc = klass.field(FIELD_NAME); } catch (e) { fdesc = null; }
                                        if (!fdesc) {
                                            // find largest byte[] field heuristic
                                            try {
                                                let candidate = null;
                                                klass.fields.forEach(ff => {
                                                    try {
                                                        // try read but don't crash
                                                        const rv = instance.field(ff.name).value;
                                                        const u8 = managedToUint8(rv);
                                                        if (u8 && u8.length > 0) {
                                                            if (!candidate || u8.length > candidate.len) candidate = { name: ff.name, len: u8.length, val: rv };
                                                        }
                                                    } catch (e) {}
                                                });
                                                if (candidate) fdesc = { name: candidate.name };
                                            } catch (e) {}
                                        }

                                        if (!fdesc) {
                                            // nothing found, maybe field set later; bail out if tries exceeded
                                            if (tries >= maxTries) { clearInterval(checkInterval); }
                                            return;
                                        }

                                        // read field value via instance.field(...) pattern
                                        let raw = null;
                                        try {
                                            raw = instance.field(fdesc.name).value;
                                        } catch (e) { raw = null; }

                                        if (!raw || typeof raw === 'undefined' ) {
                                            if (tries >= maxTries) clearInterval(checkInterval);
                                            return; // still null
                                        }

                                        // convert to Uint8Array
                                        const u8 = managedToUint8(raw);
                                        if (!u8 || u8.length === 0) {
                                            // not a byte array; print info and stop
                                            try {
                                                // if string-like, call toString
                                                if (raw.class && raw.class.name === "String") {
                                                    console.log(`[i] ${fdesc.name} is string: "${raw.toString()}"`);
                                                    safeSend({type:"platform_register_info_string", field:fdesc.name, value: raw.toString()});
                                                } else {
                                                    console.log(`[i] ${fdesc.name} exists but no bytes (class=${raw.class ? raw.class.name : typeof raw})`);
                                                }
                                            } catch (e) {}
                                            clearInterval(checkInterval);
                                            return;
                                        }

                                        // success: we have bytes
                                        console.log(`[+] Captured ${fdesc.name} on instance ${instHandle}: ${u8.length} bytes`);
                                        console.log("    hex (first 512 bytes):", u8ToHex(u8.slice(0, Math.min(512, u8.length))));
                                        const b64 = u8ToB64(u8);
                                        safeSend({ type:"platform_register_info_dump", field: fdesc.name, length: u8.length, base64: b64 });

                                        // attempt to save to sdcard
                                        const fname = `platform_register_info_${Math.floor(Date.now()/1000)}.bin`;
                                        const wrote = writeToSdcard(fname, u8);
                                        if (!wrote) {
                                            // if write failed, host will get base64 via send()
                                        }

                                        clearInterval(checkInterval);
                                    } catch (inner) {
                                        // ignore internal failures; try again until maxTries
                                        if (tries >= maxTries) clearInterval(checkInterval);
                                    }
                                });
                                if (tries >= maxTries) clearInterval(checkInterval);
                            }, POLL_INTERVAL_MS);
                        }
                    });

                } catch (e) {
                    console.warn("[!] attach failed for", method.name, e);
                }
            });

            // done hooking targets
        } catch (outer) {
            console.warn("[!] pollAsm outer error:", outer);
        }
    }, POLL_INTERVAL_MS);
});
