<template>
    <div class="view">
        <stack
            v-for="stack in stacks"
            v-bind:stack="stack"
        />
    </div>
</template>

<script>
export default {
    data() {
        return {
            stacks: [],
        };
    }
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
