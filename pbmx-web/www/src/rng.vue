<template>
    <div class="rng">
        <div class="header">
            <div class="blob">{{ name }}</div>
            <div class="blob text">{{ spec }}</div>
            <button v-on:click="provide" v-if="state == 'entropy'">Provide entropy</button>
            <div v-if="state == 'waitEntropy'">Waiting for entropy...</div>
            <button v-on:click="reveal" v-if="state == 'reveal'">Reveal</button>
            <div v-if="state == 'waitReveal'">Waiting for reveal...</div>
            <div v-if="state == 'revealed'">{{ value }}</div>
        </div>
    </div>
</template>

<script>
import { getGame, mutGame } from "./state.js";
import { saveBlock } from "./storage.js";
import { formatBase64 } from "./display.js";
import { Payload } from "pbmx-web";

export default {
    components: { },
    props: ["rng", "name"],
    computed: {
        spec() {
            return this.rng.spec();
        },
        state() {
            return this.rng.state(getGame());
        },
        value() {
            return this.rng.value(getGame());
        },
    },
    methods: {
        async provide() {
            const mask = getGame().maskRandom();
            this.rng.addEntropy(getGame().playerFingerprint(), mask);

            const builder = getGame().buildBlock();
            builder.addPayload(Payload.randomEntropy(this.name, mask));
            if(this.rng.isGenerated()) {
                const [share, proof] = getGame().unmaskShare(this.rng.mask());
                builder.addPayload(Payload.randomReveal(this.name, share, proof));
            }
            const block = mutGame(g => g.finishBlock(builder));
            await saveBlock(block, getGame().id);
            this.$parent.$parent.lastBlock = block;
            this.$parent.$parent.exportedBlock = formatBase64(block.export());
        },
        async reveal() {
            const [share, proof] = getGame().unmaskShare(this.rng.mask());
            const builder = getGame().buildBlock();
            builder.addPayload(Payload.randomReveal(this.name, share, proof));
            const block = mutGame(g => g.finishBlock(builder));
            await saveBlock(block, getGame().id);
            this.$parent.$parent.lastBlock = block;
            this.$parent.$parent.exportedBlock = formatBase64(block.export());
        },
    },
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
