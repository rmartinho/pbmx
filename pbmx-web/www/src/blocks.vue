<template>
    <div class="view">
        <div>
            <div><textarea v-model="newBlock" :readonly="addingBlock" class="block-input" placeholder="paste a block here"></textarea></div>
            <button v-on:click="addBlock" :disabled="!newBlock || addingBlock">Add block</button>
            <button v-on:click="fetchBlocks" :disabled="addingBlock">Fetch blocks</button>
        </div>
        <div>Blocks: {{ blockCount }}</div>
        <div>
            <block
                v-for="block in blocks"
                :key="block.id().export()"
                :block="block"
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
            await saveBlock(mutGame(g => g.addBlock(block)), getGame().id);
            this.newBlock = null;
            this.addingBlock = false;
        },
        async fetchBlocks() {
            this.addingBlock = true;
            const blocks = await pullBlocks();
            for(const raw of blocks) {
                const block = Block.import(raw);
                if(!await hasBlock(block.id().export())) {
                    await saveBlock(mutGame(g => g.addBlock(block)), getGame().id);
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
