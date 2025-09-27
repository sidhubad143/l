console.log("[*] Waiting for libil2cpp.so to load...");

function findClassByNamePart(namePart) {
    var found = [];
    Il2Cpp.domain.assemblies.forEach(assembly => {
        try {
            assembly.image.classes.forEach(c => {
                if (c.name.indexOf(namePart) !== -1) {
                    found.push({ klass: c, asm: assembly.name });
                }
            });
        } catch (e) {}
    });
    return found;
}

function hookClass(klass) {
    try {
        var ctor = klass.method(".ctor");
        if (ctor) {
            console.log("[+] Hooking constructor of", klass.name);
            Interceptor.attach(ctor.virtualAddress, {
                onEnter(args) {
                    console.log("[*] PlatformRegisterReq created:", this.threadId);
                }
            });
        }
    } catch (e) {
        console.error("Hook failed:", e);
    }
}

Il2Cpp.perform(() => {
    console.log("[*] libil2cpp.so loaded, scanning for PlatformRegisterReq...");

    var matches = findClassByNamePart("PlatformRegisterReq");

    if (matches.length === 0) {
        console.log("[-] No class with 'PlatformRegisterReq' found. Try triggering login.");
        return;
    }

    matches.forEach(m => {
        console.log("[+] Found", m.klass.name, "in assembly", m.asm);
        hookClass(m.klass);
    });
});
