import { Game } from "pbmx-web";
import { reactive } from "vue";
import { getPrivateKey, loadBlocks } from "./storage.js";

let game;
let react = reactive({ tick: true });

export default async function() {
    game = Game.new(getPrivateKey());
    await asyncMutGame(loadBlocks);
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
