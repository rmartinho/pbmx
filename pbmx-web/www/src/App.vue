<template>
    <div class="app">
        <game v-if="gameLoaded"></game>
        <gameList v-if="!gameLoaded"></gameList>
    </div>
</template>

<script>
import game from "./game.vue";
import gameList from "./games.vue";
import { hasGame } from "./state.js";

export default {
    components: { game, gameList },
    data() {
        return {
            gameLoaded: hasGame(),
        };
    }
};
</script>

<style>
.app {
}
</style>

<!--
    vim:ft=html
-->
