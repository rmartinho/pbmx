import initPbmx, * as pbmx from "pbmx-web";
import { createApp } from "vue";
import App from "./App.vue";

(async function() {
    await initPbmx();
    createApp(App).mount("#app");
})();

// Hot Module Replacement (HMR) - Remove this snippet to remove HMR.
// Learn more: https://www.snowpack.dev/#hot-module-replacement
if (import.meta.hot) {
  import.meta.hot.accept();
  import.meta.hot.dispose(() => {
    app.unmount();
  });
}
