import initPbmx from "pbmx-web";
import { createApp } from "vue";
import App from "./App.vue";
import initDB from "./storage.js";
import initGame from "./state.js";

(async function() {
    await initPbmx();
    await initDB();
    if (window.location.hash) {
        const id = window.location.hash.substring(1);
        await initGame(id);
    }

    createApp(App).mount("#app");
})();
