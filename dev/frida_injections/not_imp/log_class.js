Java.perform(() => {
    Java.enumerateLoadedClasses({
        onMatch: function(name) {
            if (name.toLowerCase().includes("main")) {
                console.log("[+] Found class:", name);
            }
        },
        onComplete: function() {
            console.log("[*] Class enumeration done.");
        }
    });
});
