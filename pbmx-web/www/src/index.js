import initPbmx from "pbmx-web";
import { createApp } from "vue";
import App from "./App.vue";
import initDB from "./storage.js";
import initGame from "./state.js";

(async function() {
    await initPbmx();
    await initDB();
    await initGame();

    const app = createApp(App);
    app.mount("#app");
})();
