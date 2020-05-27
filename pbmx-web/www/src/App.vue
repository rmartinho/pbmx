<template>
  <div class="App">
    {{ message }}
  </div>
</template>

<script>
import * as pbmx from "pbmx-web";

export default {
  data() {
    return {
      message: "Welcome to PBMX; here's a private key: " + pbmx.PrivateKey.random().export()
    };
  }
};
</script>

<style>
.App {
  text-align: center;
}
</style>

<!--
    vim:ft=html
-->
