<template>
    <div class="block">
        <div class="header">
            <div class="blob">{{ id }}</div>
            <div class="blob text">{{ signer }}</div>
        </div>
        <payload
            v-for="payload in block.payloads()"
            v-bind:key="payload.id().export()"
            v-bind:payload="payload"
            />
    </div>
</template>

<script>
import identifier from "./identifier.vue";
import payload from "./payload.vue";
import { getGame } from "./state.js";
import { shortFingerprint } from "./display.vue";

export default {
    components: { identifier, payload },
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
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
