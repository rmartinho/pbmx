<template>
    <div class="view">
        <rng
            v-for="rng in rngs"
            v-bind:key="rng[0]"
            v-bind:rng="rng[1]"
        />
    </div>
</template>

<script>
import { getGame } from "./state.js";
import rng from "./rng.vue";
import { Rng } from "pbmx-web";

export default {
    components: { rng },
    computed: {
        rngs() {
            return getGame().rngs();
        },
    }
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
