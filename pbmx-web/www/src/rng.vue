<template>
    <div class="rng">
        <div class="header">
            <div class="blob">{{ key }}</div>
            <div class="blob text">{{ spec }}</div>
        </div>
    </div>
</template>

<script>
import { getGame } from "./state.js";

export default {
    components: { },
    props: ["rng"],
    computed: {
        spec() {
            return this.rng.spec();
        },
    },
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
