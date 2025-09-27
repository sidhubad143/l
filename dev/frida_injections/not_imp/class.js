// observe_ctor_dump.js
// Use inside frida-il2cpp-bridge index.js or load with frida gadget
// Observes proto.PlatformRegisterReq constructor, dumps instance fields (safe)

console.log("[*] observe_ctor_dump.js starting...");

const ASSEMBLY = "Assembly-CSharp";
const CLASS_NAME = "proto.PlatformRegisterReq";
const POLL_MS = 200;

// helpers
function u8ToHex(u8) { return Array.from(u8 || []).map(b => b.toString(16).padStart(2,'0')).join(' '); }
function u8ToAscii(u8) { return Array.from(u8 || []).map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join(''); }
function u8ToBase64(u8) {
    try {
        const binary = Array.prototype.map.call(u8, v => String.fromCharCode(v)).join('');
        return btoa(binary);
    } catch (e) { return null; }
}
function tryToUint8Array(fieldVal) {
    if (!fieldVal) return null;
    try {
        if (typeof fieldVal.length === 'number') {
            const arr = new Uint8Array(fieldVal.length);
            for (let i = 0; i < fieldVal.length; i++) arr[i] = fieldVal.get(i) & 0xff;
            return arr;
        }
    } catch (e) {}
    try { if (fieldVal.byteLength) return new Uint8Array(fieldVal); } catch(e){}
    return null;
}

// poll until class loaded
const poll = setInterval(() => {
    try {
        const asm = Il2Cpp.domain.assembly(ASSEMBLY);
        if (!asm) return;
        const klass = asm.image.tryClass(CLASS_NAME) || asm.image.tryClass("PlatformRegisterReq");
        if (!klass) return;

        clearInterval(poll);
        console.log("[+] Found", klass.name, "in", asm.name);
        attachCtorObserver(klass);
    } catch (e) {
        // continue polling
    }
}, POLL_MS);

function attachCtorObserver(klass) {
    try {
        const ctor = klass.method(".ctor");
        if (!ctor) {
            console.error("[-] No constructor method found");
            return;
        }

        const addr = ptr(ctor.virtualAddress);
        console.log("[*] ctor native address:", addr);

        Interceptor.attach(addr, {
            onEnter: function (args) {
                // capture the this pointer passed to ctor; args[0] is 'this' on both ARM and ARM64
                this.instancePtr = args[0];
            },
            onLeave: function (retval) {
                const instPtr = this.instancePtr;
                if (!instPtr || instPtr.isNull && instPtr.isNull()) {
                    console.warn("[!] ctor leave but instancePtr is null");
                    return;
                }

                // Use Il2Cpp.perform to attach current thread and safely use bridge APIs
                try {
                    Il2Cpp.perform(() => {
                        try {
                            const obj = new Il2Cpp.Object(instPtr); // managed wrapper for the instance
                            console.log("\n[+] PlatformRegisterReq instance observed at", instPtr);
                            // dump fields
                            klass.fields.forEach(f => {
                                try {
                                    // read via obj.field(name).value which is reliable in bridge
                                    let fv = obj.field(f.name).value;
                                    if (fv === null || typeof fv === 'undefined') {
                                        console.log(`   ${f.name}: <null>`);
                                        return;
                                    }
                                    // try byte[]
                                    const u8 = tryToUint8Array(fv);
                                    if (u8 && u8.length > 0) {
                                        console.log(`   ${f.name}: [${u8.length} bytes]`);
                                        console.log("     hex:", u8ToHex(u8));
                                        console.log("     ascii:", u8ToAscii(u8));
                                        const b64 = u8ToBase64(u8);
                                        if (b64) {
                                            // send to host for saving/analysis
                                            try { send({ type: "platform_register_field", field: f.name, length: u8.length, base64: b64 }); } catch(e){}
                                        }
                                    } else {
                                        // string/number/enum
                                        try { console.log(`   ${f.name}: ${JSON.stringify(fv)}`); } catch(e){ console.log(`   ${f.name}: <unprintable>`); }
                                    }
                                } catch (fe) {
                                    console.log(`   ${f.name}: <error reading> (${fe})`);
                                }
                            });
                            console.log("--------------------------------------------------");
                        } catch (inner) {
                            console.warn("[!] Il2Cpp.perform inner error:", inner);
                        }
                    });
                } catch (e) {
                    console.warn("[!] Failed to Il2Cpp.perform:", e);
                }
            }
        });

        console.log("[+] Interceptor attached to ctor; trigger registration/login in app now.");
    } catch (e) {
        console.error("[-] attachCtorObserver error:", e);
    }
}
