// nativelog.js
// This script is designed for a Frida Gadget setup.

console.log("[*] Frida script started. Il2Cpp is available.");

try {
    // --- Step 1: Find the PlatformRegisterReq class ---
    var assemblyNames = ["Assembly-CSharp-firstpass", "Assembly-CSharp", "Assembly-CSharp-firstpass.dll", "Assembly-CSharp.dll"];
    var className = "proto.PlatformRegisterReq";
    var platformRegisterReqClass = null;
    var foundAssembly = null;

    for (var i = 0; i < assemblyNames.length; i++) {
        var name = assemblyNames[i];
        try {
            platformRegisterReqClass = Il2Cpp.domain.assembly(name).image.class(className);
            if (platformRegisterReqClass) {
                foundAssembly = name;
                break;
            }
        } catch (e) {
            console.log("[-] Class not found in assembly:", name);
        }
    }

    if (platformRegisterReqClass) {
        console.log("[+] Found PlatformRegisterReq class in assembly:", foundAssembly);
        console.log("[+] Class address:", platformRegisterReqClass.handle);
        
        // --- Step 2: Find the constructor method (.ctor) ---
        var constructorMethod = platformRegisterReqClass.method(".ctor");
        
        if (constructorMethod) {
            console.log("[+] Found constructor for PlatformRegisterReq at address:", constructorMethod.virtualAddress);
            
            // --- Step 3: Intercept the constructor ---
            Interceptor.attach(constructorMethod.virtualAddress, {
                onLeave: function(retval) {
                    console.log("--------------------------------------------------");
                    console.log("[*] PlatformRegisterReq object created! Looking for the caller...");
                    var backtrace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n');
                    console.log("Call Stack:\n" + backtrace);
                    console.log("--------------------------------------------------");
                }
            });
        } else {
            console.log("[-] Could not find constructor for PlatformRegisterReq.");
        }
    } else {
        console.log("[-] Could not find PlatformRegisterReq class in any of the common assemblies.");
        console.log("[-] Listing all available assemblies for manual check:");
        Il2Cpp.domain.assemblies.forEach(function(assembly) {
            console.log("  -", assembly.name);
        });
    }

} catch (e) {
    console.error("Error in Frida script:", e);
}
