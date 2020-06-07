import initPbmx from "pbmx-web";
import { createApp } from "vue";
import App from "./App.vue";
import initDB from "./storage.js";

(async function() {
    await initPbmx();
    await initDB();

    const app = createApp(App);
    app.mount("#app");
})();
