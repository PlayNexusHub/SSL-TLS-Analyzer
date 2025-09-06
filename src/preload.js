const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // SSL/TLS analysis
  analyzeSSL: (hostname, port) => ipcRenderer.invoke('analyze-ssl', hostname, port),
  getCertificate: (hostname, port) => ipcRenderer.invoke('get-certificate', hostname, port),
  testCipherSuites: (hostname, port) => ipcRenderer.invoke('test-cipher-suites', hostname, port),
  validateCertChain: (hostname, port) => ipcRenderer.invoke('validate-cert-chain', hostname, port),
  
  // Settings
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  loadSettings: () => ipcRenderer.invoke('load-settings'),
  
  // Menu events
  onMenuNewAnalysis: (callback) => ipcRenderer.on('menu-new-analysis', callback),
  onMenuCertChain: (callback) => ipcRenderer.on('menu-cert-chain', callback),
  onMenuCipherSuites: (callback) => ipcRenderer.on('menu-cipher-suites', callback),
  onMenuSettings: (callback) => ipcRenderer.on('menu-settings', callback),
  onExportCertificate: (callback) => ipcRenderer.on('export-certificate', callback),
  
  // Remove listeners
  removeAllListeners: (channel) => ipcRenderer.removeAllListeners(channel),
  
  // Utility
  getVersion: () => process.versions.electron,
  getPlatform: () => process.platform
});
