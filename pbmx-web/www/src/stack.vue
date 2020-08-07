<!-- v-bind:key="block.id().export()" -->
<template>
    <div class="stack">
        <div class="blob">235A7B34</div>
        <div class="blob text">deck</div>
        <div class="token-list">
            <div
                v-for="token in tokens"
                v-bind:token="token"
                v-bind:class="{ visible: false, selected: false }"
                class="token"
            >
                {{ token.display() }}
            </div>
        </div>
    </div>
</template>

<script>
export default {
    data() {
        return {
            tokens: [],
        };
    }
};
</script>

<style>
.stack {
  padding: 50px;
}
.blob {
  border-radius: 4px;
  box-shadow: inset 1px 1px #666;
  background: white;
  padding-left: 5px;
  font-family: monospace;
  text-align: center;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  width: auto;
  margin-bottom: 2px;
}
.text,
.token {
  font-family: sans-serif;
}

.token-list {
  transform: perspective(900px);
  transform-style: preserve-3d;
  perspective-origin: 50% 30%;
}

.token {
  display: none;
  transition: all @transition-time ease;
  transform: rotateY(45deg);
  border: 1px solid;
  border-radius: 5px;
  font-size: 100pt;
  width: 180px;
  height: 180px;
  margin: 0 -60px 0 0;
  position: relative;
  box-shadow: 0 1px 8px rgba(0, 0, 0, 0.9);
  opacity: 100%;
  background: white;
}
.token + .token {
  margin: 0 -60px 0 -60px;
}
.selected {
  transform: rotateY(0deg);
  margin: 0 auto;
  transition: all @transition-time ease;
}
.token + .selected {
  margin: 0 auto;
}
.selected ~ .token {
  transform: rotateY(-45deg);
}
.selected ~ .selected {
  transform: rotateY(0deg);
}
.visible {
  display: inline-block;
}
</style>

<!--
    vim:ft=html
-->

