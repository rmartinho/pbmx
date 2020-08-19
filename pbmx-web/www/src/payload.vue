<template>
    <div>
        <!--<component :is="component"></component>-->
    </div>
</template>

<script>
//import pubkey from "./payload-pubkey.vue";

//const components = { pubkey };

export default {
    props: ["payload"],
    computed: {
        //component() {
        //    return components[payload.kind()];
        //},
    },
};
</script>

<style>
</style>

<!--
    vim:ft=html
-->
