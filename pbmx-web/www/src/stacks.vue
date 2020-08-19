<template>
    <div class="view">
        <stack
            v-for="stack in stacks"
            :stack="stack"
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
