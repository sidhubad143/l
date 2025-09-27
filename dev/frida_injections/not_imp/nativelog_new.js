// nativelog.js (Workaround)
// This script uses Interceptor.replace as a workaround for a broken Interceptor.attach.
// Note: This is an advanced technique and may not work depending on the nature of the bug.

console.log("[*] Frida script started. Il2Cpp is available.");

try {
    // --- Find the constructor's address first ---
    var assemblyName = "Assembly-CSharp";
    var className = "proto.PlatformRegisterReq";
    var platformRegisterReqClass = Il2Cpp.domain.assembly(assemblyName).image.class(className);
    
    if (!platformRegisterReqClass) {
        throw new Error("Could not find class " + className + " in assembly " + assemblyName);
    }
    
    var constructorMethod = platformRegisterReqClass.method(".ctor");
    if (!constructorMethod) {
        throw new Error("Could not find constructor for " + className);
    }
    
    var constructorAddress = constructorMethod.virtualAddress;
    console.log("[+] Found constructor at address:", constructorAddress);

    // --- Define the original constructor function ---
    // We need to call the original constructor to not break the app.
    var originalCtor = new NativeFunction(constructorAddress, 'void', ['pointer']);
    
    // --- Create a custom C function to replace the original one ---
    // This function will execute our logic (logging) and then call the original constructor.
    var customCtor = new NativeCallback(function(instance_ptr) {
        // Log the stack trace before calling the original constructor.
        console.log("--------------------------------------------------");
        console.log("[*] Interceptor.replace called!");
        var backtrace = Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\n');
        console.log("Call Stack:\n" + backtrace);
        console.log("--------------------------------------------------");

        // Call the original function to complete the object's creation.
        originalCtor(instance_ptr);
    }, 'void', ['pointer']);

    // --- Replace the original constructor with our custom one ---
    // This is the part that might bypass the bug in your installation.
    Interceptor.replace(constructorAddress, customCtor);
    console.log("[+] Constructor replaced successfully. Waiting for a call...");

} catch (e) {
    console.error("Error in Frida script:", e);
}
