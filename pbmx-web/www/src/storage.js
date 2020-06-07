import { PrivateKey } from "pbmx-web";

function init() {
    return new Promise((resolve, reject) => {
        const existing = localStorage.getItem("privateKey");
        if(!existing) {
            localStorage.setItem("privateKey", PrivateKey.random().export());
        } else {
            PrivateKey.import(existing);
        }

        const req = indexedDB.open("pbmx", 1);
        req.onupgradeneeded = function() {
            const db = req.result;
            if(!db.objectStoreNames.contains("games")) {
                db.createObjectStore("games", { keyPath: "name" });
            }
            if(!db.objectStoreNames.contains("blocks")) {
                const blocks = db.createObjectStore("blocks", { keyPath: "id" });
                blocks.createIndex('game', 'game');
            }
        };
        req.onsuccess = function() {
            resolve(req.result);
        };
        req.onerror = function() {
            reject(req.error);
        };
    });
}

export function getPrivateKey() {
    const base64 = localStorage.getItem("privateKey");
    return PrivateKey.import(base64);
}

export default init;
