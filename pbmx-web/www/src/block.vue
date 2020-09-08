<template>
    <div class="block">
        <div class="header">
            <div class="blob">{{ id }}</div>
            <div class="blob text">{{ signer }}</div>
        </div>
        <payload
            v-for="payload in block.payloads()"
            :key="payload.id().export()"
            :payload="payload"
            />
        <button v-on:click="getRaw">Raw</button>
    </div>
</template>

<script>
import payload from "./payload.vue";
import { getGame } from "./state.js";
import { formatBase64, shortFingerprint } from "./display.vue";

export default {
    components: { payload },
    props: ["block"],
    computed: {
        id() {
            return shortFingerprint(this.block.id().export());
        },
        signer() {
            const signer = this.block.signer().export();
            return getGame().players().get(signer);
        },
    },
    methods: {
        getRaw() {
            this.$parent.$parent.exportedBlock = formatBase64(this.block.export());
        },
    },
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
