<template>
    <div class="view">
        <div class="fingerprint">Game Fingerprint: {{ gameFingerprint }}</div>
        <div class="fingerprint">Your Fingerprint: {{ playerFingerprint }}</div>
    </div>
</template>

<script>
export default {
    data() {
        return {
            gameFingerprint: this.$parent.gameFingerprint,
            playerFingerprint: this.$parent.playerFingerprint
        };
    }
};
</script>

<style>
.view {
}
</style>

<!--
    vim:ft=html
-->
