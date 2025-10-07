
/*
Protective Source License v1.0 (PSL-1.0)
Copyright (c) 2025 Kaif
Unauthorized removal of credits or use for abusive/illegal purposes
will terminate all rights granted under this license.
*/

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
