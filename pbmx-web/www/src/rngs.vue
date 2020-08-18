<template>
    <div class="view">
        <rng
            v-for="rng in rngs"
            v-bind:key="rng[0]"
            v-bind:name="rng[0]"
            v-bind:rng="rng[1]"
        />
    </div>
    <div>
        <input v-model="name" placeholder="RNG name">
        <input v-model="spec" placeholder="RNG spec, e.g., 1d6+2">
        <button v-on:click="makeNew">New RNG</button>
    </div>
</template>

<script>
import { getGame, mutGame } from "./state.js";
import { saveBlock } from "./storage.js";
import { formatBase64 } from "./display.js";
import rng from "./rng.vue";
import { Payload } from "pbmx-web";

export default {
    components: { rng },
    computed: {
        rngs() {
            return getGame().rngs();
        },
    },
    methods: {
        async makeNew() {
            const builder = getGame().buildBlock();
            builder.addPayload(Payload.randomSpec(this.name, this.spec));
            builder.addPayload(Payload.randomEntropy(this.name, getGame().maskRandom()));
            const block = mutGame(g => g.finishBlock(builder));
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
