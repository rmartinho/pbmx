import autobahn from "autobahn-browser";
import { getGame } from "./state.js";

let server = {
    url: "wss://pbmx.herokuapp.com/ws",
    realm: "pbmx"
};

const newBlockTopic = "io.pbmx.block.new";
const getBlocksTopic = "io.pbmx.block.get";

export function setServer(url = "wss://pbmx.herokuapp.com/ws", realm = "pbmx") {
    server = { url: url, realm: realm };
}

export function pushBlock(block) {
    return new Promise((resolve, reject) => {
        const gameId = getGame().fingerprint().export();
        const blockId = block.id().export();
        const blockRaw = block.export();

        const conn = new autobahn.Connection(server);
        conn.onopen = session => {
            const args = [gameId, blockId, blockRaw];
            const options = { acknowledge: true };
            session.publish(newBlockTopic, args, {}, options).then(
                () => {
                    conn.close();
                    resolve()
                },
                e => reject(e),
            );
        };
        conn.open();
    });
}

export function getBlocks(days = 7) {
    return new Promise((resolve, reject) => {
        const gameId = getGame().fingerprint().export();

        const conn = new autobahn.Connection(server);
        conn.onopen = session => {
            const args = [gameId, days];
            session.call(getBlocksTopic, args).then(
                r => {
                    conn.close();
                    resolve(r);
                },
                e => reject(e),
            );
        };
        conn.open();
    });
}
