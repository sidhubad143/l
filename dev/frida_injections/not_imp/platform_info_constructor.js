(() => {
  const hexdump = (buffer) => {
    if (!buffer) return "<empty>";
    if (typeof Buffer !== "undefined") {
      return Buffer.from(buffer).toString('hex').match(/.{1,2}/g).join(' ');
    }
    // Fallback hexdump for environments without Buffer:
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join(' ');
  };

  console.log("[*] Starting robust hook for PlatformRegisterReq...");

  const assemblyName = "Assembly-CSharp";
  const classFullName = "proto.PlatformRegisterReq";

  function waitForClassAndHook() {
    const asm = Il2Cpp.domain.assembly(assemblyName);
    if (!asm) return false;

    const klass = asm.image.tryClass(classFullName);
    if (!klass) return false;

    console.log(`[+] Found class ${classFullName} in assembly ${assemblyName}`);

    hookMethods(klass);
    return true;
  }

  function hookMethods(klass) {
    klass.methods.forEach(method => {
      if (!method.implementation) {
        console.log(`[!] Skipping method ${method.name} - no implementation`);
        return;
      }

      const origImpl = method.implementation;

      method.implementation = function (...args) {
        const before = this.platform_register_info;
        const ret = origImpl.apply(this, args);
        const after = this.platform_register_info;

        if (before !== after) {
          console.log(`[!] platform_register_info changed in method: ${method.name}`);
          if (after && typeof after.readByteArray === "function") {
            const size = after.length || 0;
            const bytes = after.readByteArray(size);
            console.log(`    New bytes (${size} bytes):\n${hexdump(bytes)}`);
          } else {
            console.log("    New value is null or not a byte array");
          }
        }
        return ret;
      };
    });

    console.log(`[+] Hooked ${klass.methods.length} methods of ${klass.name}`);
  }

  // Poll every 200ms until class is found and hooked
  const intervalId = setInterval(() => {
    if (waitForClassAndHook()) {
      clearInterval(intervalId);
    }
  }, 200);
})();
