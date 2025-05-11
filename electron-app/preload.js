// electron-app/preload.js

const { contextBridge,ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("electronAPI", {
  apiUrl: "http://127.0.0.1:5001/analyze",
  openFileDialog: () => ipcRenderer.invoke("dialog:openFile"),

});

