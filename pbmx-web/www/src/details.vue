<template>
    <div class="view">
        <div v-if="joined">
            <div>Game fingerprint</div>
            <identifier :value="gameFingerprint"/>
        </div>
        <div>
            <div>Your fingerprint</div>
            <identifier :value="playerFingerprint"/>
        </div>
        <div v-if="!joined">
            You have not joined this game.
            <input v-model="name" placeholder="your nickname">
            <button v-on:click="join">Join</button>
        </div>
        <div class="player-list">
            <div v-for="player in players"
                 :key="player.id"
            >
                {{ player.name }} : <identifier inline :value="player.id"/>
            </div>
        </div>
    </div>
</template>

<script>
import identifier from "./identifier.vue";
import { saveBlock } from "./storage.js";
import { getGame, mutGame } from "./state.js";
import { shortFingerprint, formatBase64 } from "./display.js";

export default {
    components: { identifier },
    data() {
        return {
            name: null,
        };
    },
    computed: {
        gameFingerprint() {
            return shortFingerprint(getGame().fingerprint().export());
        },
        playerFingerprint() {
            return shortFingerprint(getGame().playerFingerprint().export());
        },
        players() {
            const arr = [];
            for(const player of getGame().players()) {
                arr.push({ name: player[1], id: shortFingerprint(player[0]) });
            }
            return arr;
        },
        joined() {
            return getGame().joined();
        },
    },
    methods: {
        async join() {
            const block = mutGame(g => g.finishBlock(g.join(this.name)));
            await saveBlock(block, getGame().id);
            this.$parent.lastBlock = block;
            this.$parent.exportedBlock = formatBase64(block.export());
        },
    },
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
