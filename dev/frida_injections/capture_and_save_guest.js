/*
Protective Source License v1.0 (PSL-1.0)
Copyright (c) 2025 Kaif
Unauthorized removal of credits or use for abusive/illegal purposes
will terminate all rights granted under this license.
*/


// guest_data_capture_final_v6.js
// Script to correctly capture, append, and save all guest credentials.
setImmediate(function(){
Java.perform(function () {
    console.log("[*] Script started. Initializing hooks...");

    // ---- Helper Functions ----
    function log(s) { console.log(s); }
    
    var guestDataBuffer = {}; 
    var guestList = [];
    var saveDelay = 200; // Adjusted delay to 200ms
    var saveTimer = null;

    // Helper: Read existing JSON data from file
    function readExistingGuests() {
        var reader = null;
        try {
            var File = Java.use("java.io.File");
            var BufferedReader = Java.use("java.io.BufferedReader");
            var FileReader = Java.use("java.io.FileReader");
            var Context = Java.use("android.content.Context");
            var ActivityThread = Java.use("android.app.ActivityThread");
            
            var appContext = ActivityThread.currentApplication().getApplicationContext();
            var mediaDirs = appContext.getExternalMediaDirs();
            var baseDir = mediaDirs[0].getAbsolutePath();
            var filePath = baseDir + "/guest_accounts.json";
            
            var file = File.$new(filePath);
            
            if (file.exists()) {
                log("[*] Found existing guest data file. Reading content...");
                reader = BufferedReader.$new(FileReader.$new(file));
                var line;
                var jsonStr = "";
                while ((line = reader.readLine()) !== null) {
                    jsonStr += line;
                }
                guestList = JSON.parse(jsonStr);
                log("[*] Loaded " + guestList.length + " existing guests.");
            }
        } catch (e) {
            log("[!] Error reading existing JSON file: " + e);
            // If the file is not valid JSON, we'll start with an empty list.
            guestList = []; 
        } finally {
            if (reader) {
                try {
                    reader.close();
                } catch(e) {}
            }
        }
    }

    // Helper: Write JSON array to file
    function writeJsonFile() {
        var writer = null;
        try {
            var File = Java.use("java.io.File");
            var FileWriter = Java.use("java.io.FileWriter");
            var BufferedWriter = Java.use("java.io.BufferedWriter");
            var Context = Java.use("android.content.Context");
            var ActivityThread = Java.use("android.app.ActivityThread");
            
            var appContext = ActivityThread.currentApplication().getApplicationContext();
            var mediaDirs = appContext.getExternalMediaDirs();
            var baseDir = mediaDirs[0].getAbsolutePath();
            var filePath = baseDir + "/guest_accounts.json";
            
            var file = File.$new(filePath);
            
            // The FileWriter constructor with `false` will overwrite the file.
            // We're doing this intentionally here because we've already
            // loaded the existing data and we're writing the complete list back.
            writer = BufferedWriter.$new(FileWriter.$new(file, false)); 
            
            var jsonStr = JSON.stringify(guestList, null, 2);
            
            var CharArray = Java.array('char', jsonStr.split(''));
            writer.write(CharArray, 0, CharArray.length);
            
            log("[*] Saved guest data JSON to: " + filePath);
        } catch (e) {
            log("[!] Error writing JSON file: " + e);
            log(e.stack);
        } finally {
            if (writer) {
                try {
                    writer.close();
                } catch(e) {}
            }
        }
    }

    // This function adds the buffer to the list and saves to file
    function saveAndClearBuffer() {
        if (Object.keys(guestDataBuffer).length === 0) {
            log("[!] No guest data available to save.");
            return;
        }

        var newGuest = {
            uid: guestDataBuffer.uid || "unknown_uid",
            password: guestDataBuffer.password || "unknown_password",
            token: guestDataBuffer.token || "unknown_token"
        };
        log("[*] Guest credentials captured: " + JSON.stringify(newGuest));
        
        var isDuplicate = guestList.some(item => item.uid === newGuest.uid && item.password === newGuest.password && item.token === newGuest.token);
        if (!isDuplicate) {
            guestList.push(newGuest);
            writeJsonFile();
        } else {
            log("[*] Detected duplicate guest data, not saving.");
        }
        
        guestDataBuffer = {};
    }

    // This function is the new entry point for saving data.
    // It starts or resets a timer.
    function triggerSave() {
        if (saveTimer) {
            clearTimeout(saveTimer);
        }
        saveTimer = setTimeout(saveAndClearBuffer, saveDelay);
        log("[*] Triggering delayed save in " + saveDelay + "ms...");
    }
    
    // ---- Blocking Hooks ----
    var AM = Java.use("android.accounts.AccountManager");
    AM.getAccountsByType.overload('java.lang.String').implementation = function (type) {
        if (type.indexOf("garena") >= 0 || type.indexOf("msdk") >= 0) {
            log("[BLOCK] AccountManager.getAccountsByType(" + type + ") -> []");
            return Java.array("android.accounts.Account", []);
        }
        return this.getAccountsByType(type);
    };
    AM.addAccountExplicitly.overload('android.accounts.Account', 'java.lang.String', 'android.os.Bundle').implementation = function (account, password, userdata) {
        log("[BLOCK] AccountManager.addAccountExplicitly() -> blocked");
        return false;
    };

    var SP = Java.use("android.app.SharedPreferencesImpl");
    SP.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        if (key.indexOf("guest") >= 0 || key.indexOf("msdk") >= 0) {
            log("[BLOCK] SharedPreferences.getString(" + key + ") -> null");
            return null;
        }
        return this.getString(key, defValue);
    };

    var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    Editor.putString.implementation = function (key, value) {
        log("[SP] putString(" + key + ")");

        if (key === "com.garena.msdk.guest_uid") {
            log("[*] SharedPreferences: Identified UID.");
            guestDataBuffer.uid = value;
            triggerSave();
        } else if (key === "com.garena.msdk.guest_password") {
            log("[*] SharedPreferences: Identified Password.");
            guestDataBuffer.password = value;
            triggerSave();
        } else if (key === "com.garena.msdk.token" || key === "com.garena.msdk.guest_token") {
            log("[*] SharedPreferences: Identified Token.");
            guestDataBuffer.token = value;
            triggerSave();
        }
        
        return this;
    };
    
    log("[*] AccountManager & SharedPreferences hooks installed.");


    // ---- d2.k Class Hooks ----
    var targetClass = "d2.k";
    var tries = 0;
    var max = 60;

    var interval = setInterval(function () {
        tries++;
        try {
            var C = Java.use(targetClass);
            clearInterval(interval);
            log("[+] Found class: " + targetClass + " (hooking methods)");

            C.j.overloads.forEach(function (ov) {
                ov.implementation = function (key, value) {
                    log("\n=== d2.k.j(key,value) called ===");
                    log(" key: " + key);
                    log(" value: " + value);

                    if (value && value.length > 30 && value.match(/^[0-9a-fA-F]+$/)) {
                        log("[*] d2.k.j: Identified a potential guest password.");
                        guestDataBuffer.password = value;
                        triggerSave();
                    } else if (value && value.length >= 10 && value.match(/^[0-9]+$/)) {
                        log("[*] d2.k.j: Identified a potential guest UID.");
                        guestDataBuffer.uid = value;
                        triggerSave();
                    }
                    
                    return ov.apply(this, arguments);
                };
            });
            log(" - hooked j(String,String)");

            C.c.overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var ret = ov.apply(this, arguments);
                    log("\n=== d2.k.c() called (guest_password getter) ===");
                    log("-> returned: " + ret);
                    return ret;
                };
            });
            log(" - hooked c()");
            
            log("[*] Hooks installed. Please trigger guest creation in-app.");

        } catch (err) {
            if (tries >= max) {
                clearInterval(interval);
                log("[-] Timeout: class " + targetClass + " not found.");
            }
        }
    }, 300);
    
    // Read any existing guests into the list when the script starts
    readExistingGuests();
});
});
