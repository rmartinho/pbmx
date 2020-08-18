import { PrivateKey, Block } from "pbmx-web";

let db;

export default function() {
    return new Promise((resolve, reject) => {
        const existing = window.localStorage.getItem("privateKey");
        if(!existing) {
            window.localStorage.setItem("privateKey", PrivateKey.random().export());
        } else {
            PrivateKey.import(existing);
        }

        const req = window.indexedDB.open("pbmx", 1);
        req.onupgradeneeded = () => {
            const db = req.result;
            if(!db.objectStoreNames.contains("games")) {
                db.createObjectStore("games", { keyPath: "id" });
            }
            if(!db.objectStoreNames.contains("blocks")) {
                const blocks = db.createObjectStore("blocks", { keyPath: "id" });
                blocks.createIndex("game", "game");
            }
        };
        req.onsuccess = () => {
            db = req.result;
            resolve(db);
        };
        req.onerror = () => reject(req.error);
    });
}

export function debugReset() {
    return new Promise((resolve, reject) => {
        const tx = db.transaction("blocks", "readwrite");
        const req = tx.objectStore("blocks").clear();
        req.onsuccess = resolve;
        req.onerror = () => reject(req.error);
    });
}

export function getPrivateKey() {
    const base64 = window.localStorage.getItem("privateKey");
    return PrivateKey.import(base64);
}

function saveGame(tx, gameObj) {
    return new Promise((resolve, reject) => {
        const req = tx.objectStore("games").put(gameObj);
        req.onsuccess = resolve;
        req.onerror = () => {
            reject(req.error);
        };
    });
}

export function saveBlock(block, gameId) {
    return new Promise((resolve, reject) => {
        if(!gameId) {
            gameId = "00000000000000000000000000000000";
        }
        const gameObj = {
            id: gameId,
        };
        const blockObj = {
            id: block.id().export(),
            data: block.export(),
            game: gameId,
        };
        const tx = db.transaction(["games", "blocks"], "readwrite");
        saveGame(tx, gameObj).then(() => {
            const req = tx.objectStore("blocks").add(blockObj);
            req.onsuccess = resolve;
            req.onerror = () => reject(req.error);
        }, reject);
    });
}

export function hasBlock(id) {
    return new Promise((resolve, reject) => {
        getBlock(id).then(
            r => {
                resolve(!!r);
            },
            e => {
                if(e instanceof DataError) {
                    resolve(false);
                } else {
                    reject(e);
                }
            });
    });
}

function getBlock(id) {
    return new Promise((resolve, reject) => {
        const tx = db.transaction("blocks");
        const store = tx.objectStore("blocks");
        const req = store.get(id);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

function getBlocksFor(gameId) {
    return new Promise((resolve, reject) => {
        if(!gameId) {
            gameId = new Uint8Array(16);
        }
        const tx = db.transaction("blocks");
        const idx = tx.objectStore("blocks").index("game");
        const req = idx.getAll(gameId);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}

export async function loadBlocks(game) {
    const blocks = await getBlocksFor(game.id);
    for(const b of blocks) {
        game.addBlock(Block.import(b.data));
    }
}

export async function getGames() {
    return new Promise((resolve, reject) => {
        const tx = db.transaction("games");
        const store = tx.objectStore("games");
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
}
