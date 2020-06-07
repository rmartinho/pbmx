<template>
    <div class="game">
        <button
            v-for="tab in tabs"
            v-bind:key="tab.name"
            v-bind:class="{ active: currentTab.name === tab.name }"
            v-on:click="currentTab = tab" 
            class="tab-button"
        >{{ tab.name }}</button>
        <component v-bind:is="currentTab.component" class="tab"></component>
        {{ blocks }}
        <button v-on:click="addBlock">Add empty block</button>
    </div>
</template>

<script>
import stacks from "./stacks.vue";
import rngs from "./rngs.vue";
import details from "./details.vue";

import { getPrivateKey } from "./storage.js";
import { Chain, Vtmf, Payload } from "pbmx-web";

const tabs = [
    {
        name: "Details",
        component: details
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
            vtmf: Vtmf.new(getPrivateKey()),
            chain: Chain.new(),
            stacks: [],
            rngs: [],
            players: [],
            chainRef: true,
        };
    },
    computed: {
        gameFingerprint() {
            return this.vtmf.sharedKey().fingerprint().export();
        },
        playerFingerprint() {
            return this.vtmf.privateKey().publicKey().fingerprint().export();
        },
        blocks() {
            this.chainRef;
            return this.chain.count();
        }
    },
    methods: {
        addBlock() {
            const sk = this.vtmf.privateKey();
            const builder = this.chain.buildBlock();
            builder.addPayload(Payload.publishKey("test", sk.publicKey()));
            const block = builder.build(sk);
            console.log(block.export());
            this.chain.addBlock(block);
            this.chainRef = !this.chainRef;
        }
    }
};
</script>

<style>
.game {
}
.tab {
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
</style>

<!--
    vim:ft=html
-->
