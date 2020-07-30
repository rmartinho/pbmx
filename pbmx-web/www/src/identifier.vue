<template>
    <div class="identifier">
        {{ value }}
    </div>
</template>

<script>
export default {
    props: ["value"]
};
</script>

<style>
.identifier {
    font-family: monospace;
    font-size: 120%;
}
.identifier[inline] {
    display: inline-block;
}
</style>

<!--
    vim:ft=html
-->
