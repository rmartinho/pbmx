import { Game } from "pbmx-web";
import { reactive } from "vue";
import { getPrivateKey, loadBlocks } from "./storage.js";
import { arrayToHex } from "./display.js";

let game;
const react = reactive({ tick: true });

export default async function(id) {
    game = Game.new(getPrivateKey());
    if(!id) {
        id = new Uint8Array(16);
        window.crypto.getRandomValues(id);
        id = arrayToHex(id);
    }
    game.id = id;
    await asyncMutGame(loadBlocks);
}

export function hasGame() {
    react.tick;
    if(game) {
        return true;
    } else {
        return false;
    }
}
export function getGame() {
    react.tick;
    return game;
}

export function mutGame(fun) {
    let result = fun(game);
    react.tick = !react.tick;
    return result;
}

export async function asyncMutGame(fun) {
    let result = await fun(game);
    react.tick = !react.tick;
    return result;
}
