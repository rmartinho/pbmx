<template>
    <div class="gameList">
        <button v-on:click="start">New game</button>
        <div
            v-for="game in games.value"
            v-bind:key="game.id"
        >
            <button v-on:click="load(game)">{{ game.id }}</button>
        </div>
    </div>
</template>

<script>
import { reactive } from "vue";
import { getGames } from "./storage.js";
import initGame, { getGame } from "./state.js";

function reactivePromise(p) {
    const react = reactive({ value: undefined });
    p.then(r => react.value = r);
    return react;
}

export default {
    data() {
        return {
            games: reactivePromise(getGames()),
        };
    },
    methods: {
        async start() {
            await initGame();
            window.location.href = window.location.href + "#" + getGame().id;
            window.location.reload();
        },
        load(game) {
            window.location.href = window.location.href + "#" + game.id;
            window.location.reload();
        }
    },
};
</script>

<style>
.game {
}
.tab {
    display: inline-block;
    border-bottom-left-radius: 3px;
    border-bottom-right-radius: 3px;
    border: 1px solid #ccc;
    padding: 10px;
}
.tab-button {
    padding: 6px 10px;
    border-top-left-radius: 3px;
    border-top-right-radius: 3px;
    border: 1px solid #ccc;
    cursor: pointer;
    background: #f0f0f0;
    margin-bottom: -1px;
    margin-right: -1px;
}
.tab-button:hover {
    background: #e0e0e0;
}
.tab-button.active {
    background: #e0e0e0;
}
.export-block {
    display: inline-block;
    border-radius: 3px;
    border: 1px solid #ccc;
    padding: 10px;
}
pre.block-output {
    display: inline-block;
    border-radius: 3px;
    border: 1px solid #ccc;
    padding: 10px;
}
</style>

<!--
    vim:ft=html
-->
