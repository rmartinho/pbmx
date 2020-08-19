<template>
    <div class="game">
        <button
            v-for="tab in tabs"
            :key="tab.name"
            :class="{ active: currentTab.name === tab.name }"
            v-on:click="currentTab = tab" 
            class="tab-button"
        >{{ tab.name }}</button>
        <div>
            <component :is="currentTab.component" class="tab"></component>
        </div>
        <div v-if="exportedBlock">
            <div class="export-block">
                <div>
                    <pre class="block-output">{{ exportedBlock }}</pre>
                </div>
                <button :disabled="publishing" v-on:click="publishBlock">Publish</button>
                <button :disabled="publishing" v-on:click="exportedBlock = null">Done</button>
            </div>
        </div>
        <button v-on:click="resetGame">RESET</button>
    </div>
</template>

<script>
import stacks from "./stacks.vue";
import rngs from "./rngs.vue";
import blocks from "./blocks.vue";
import details from "./details.vue";
import { debugReset } from "./storage.js";
import { pushBlock } from "./exchange.js";

const tabs = [
    {
        name: "Details",
        component: details
    },
    {
        name: "Blocks",
        component: blocks
    },
    {
        name: "Stacks",
        component: stacks
    },
    {
        name: "RNGs",
        component: rngs
    }
];

export default {
    data() {
        return {
            tabs: tabs,
            currentTab: tabs[0],
            lastBlock: null,
            exportedBlock: null,
            publishing: false,
        };
    },
    methods: {
        async resetGame() {
            await debugReset();
            location.reload();
        },
        async publishBlock() {
            this.publishing = true;
            await pushBlock(this.lastBlock);
            this.publishing = false;
            this.exportedBlock = null;
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
