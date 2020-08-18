import autobahn from "autobahn-browser";
import { getGame } from "./state.js";

let server = {
    url: "wss://pbmx.herokuapp.com/ws",
    realm: "pbmx"
};

const newBlockTopic = "io.pbmx.block.push";
const pullBlocksTopic = "io.pbmx.block.pull";

export function setServer(url = "wss://pbmx.herokuapp.com/ws", realm = "pbmx") {
    server = { url: url, realm: realm };
}

export function pushBlock(block) {
    return new Promise((resolve, reject) => {
        const gameId = getGame().id;
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

export function pullBlocks(days = 7) {
    return new Promise((resolve, reject) => {
        const gameId = getGame().id;

        const conn = new autobahn.Connection(server);
        conn.onopen = session => {
            const args = [gameId, days];
            session.call(pullBlocksTopic, args).then(
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
