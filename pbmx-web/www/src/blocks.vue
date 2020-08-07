<template>
    <div class="view">
        <div>
            <div><textarea v-model="newBlock" v-bind:readonly="addingBlock" class="block-input" placeholder="paste a block here"></textarea></div>
            <button v-on:click="addBlock" v-bind:disabled="!newBlock || addingBlock">Add block</button>
            <button v-on:click="fetchBlocks" v-bind:disabled="addingBlock">Fetch blocks</button>
        </div>
        <div>Blocks: {{ blockCount }}</div>
        <div>
            <block
                v-for="block in blocks"
                v-bind:key="block.id().export()"
                v-bind:block="block"
            />
        </div>
    </div>
</template>

<script>
import block from "./block.vue";
import { saveBlock, hasBlock } from "./storage.js";
import { getGame, mutGame } from "./state.js";
import { pullBlocks } from "./exchange.js";
import { Block } from "pbmx-web";

function glue(str) {
    return str.replace(/\s+/g, "");
}

export default {
    components: { block },
    data() {
        return {
            newBlock: null,
            addingBlock: false,
        };
    },
    computed: {
        blockCount() {
            return getGame().blockCount();
        },
        blocks() {
            return getGame().blocks();
        },
    },
    methods: {
        async addBlock() {
            this.addingBlock = true;
            const block = Block.import(glue(this.newBlock));
            await saveBlock(mutGame(g => g.addBlock(block)));
            this.newBlock = null;
            this.addingBlock = false;
        },
        async fetchBlocks() {
            this.addingBlock = true;
            let blocks = await pullBlocks();
            for(const raw of blocks) {
                const block = Block.import(raw);
                if(!await hasBlock(block.id().export())) {
                    await saveBlock(mutGame(g => g.addBlock(block)));
                }
            }
            this.addingBlock = false;
        }
    },
};
</script>

<style>
textarea.block-input {
    width: 600px;
    height: 100px;
    font-family: monospace;
}
</style>

<!--
    vim:ft=html
-->
