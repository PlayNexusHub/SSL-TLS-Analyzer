const { app, BrowserWindow, Menu, ipcMain, dialog, shell } = require('electron');
const { autoUpdater } = require('electron-updater');
const Store = require('electron-store');
const path = require('path');
const tls = require('tls');
const https = require('https');
const forge = require('node-forge');
const sslChecker = require('sslchecker');

// Initialize secure store
const store = new Store({
  encryptionKey: 'playnexus-ssl-analyzer-key-2024'
});

class SSLTLSAnalyzer {
  constructor() {
    this.mainWindow = null;
    this.isDev = process.argv.includes('--dev');
    
    // Security settings
    app.whenReady().then(() => {
      this.createWindow();
      this.setupMenu();
      this.setupIPC();
      
      if (!this.isDev) {
        autoUpdater.checkForUpdatesAndNotify();
      }
    });

    app.on('window-all-closed', () => {
      if (process.platform !== 'darwin') {
        app.quit();
      }
    });

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        this.createWindow();
      }
    });
  }

  createWindow() {
    this.mainWindow = new BrowserWindow({
      width: 1300,
      height: 900,
      minWidth: 900,
      minHeight: 700,
      icon: path.join(__dirname, '../assets/icon.png'),
      webPreferences: {
        nodeIntegration: false,
        contextIsolation: true,
        enableRemoteModule: false,
        preload: path.join(__dirname, 'preload.js'),
        webSecurity: true
      },
      titleBarStyle: 'default',
      show: false
    });

    this.mainWindow.loadFile(path.join(__dirname, 'renderer/index.html'));

    this.mainWindow.once('ready-to-show', () => {
      this.mainWindow.show();
      
      if (this.isDev) {
        this.mainWindow.webContents.openDevTools();
      }
    });

    // Security: Prevent new window creation
    this.mainWindow.webContents.setWindowOpenHandler(() => {
      return { action: 'deny' };
    });

    // Security: Handle external links
    this.mainWindow.webContents.on('will-navigate', (event, navigationUrl) => {
      const parsedUrl = new URL(navigationUrl);
      
      if (parsedUrl.origin !== 'file://') {
        event.preventDefault();
        shell.openExternal(navigationUrl);
      }
    });
  }

  setupMenu() {
    const template = [
      {
        label: 'File',
        submenu: [
          {
            label: 'New Analysis',
            accelerator: 'CmdOrCtrl+N',
            click: () => {
              this.mainWindow.webContents.send('menu-new-analysis');
            }
          },
          {
            label: 'Export Certificate',
            accelerator: 'CmdOrCtrl+E',
            click: () => {
              this.exportCertificate();
            }
          },
          { type: 'separator' },
          {
            label: 'Exit',
            accelerator: process.platform === 'darwin' ? 'Cmd+Q' : 'Ctrl+Q',
            click: () => {
              app.quit();
            }
          }
        ]
      },
      {
        label: 'Tools',
        submenu: [
          {
            label: 'Certificate Chain',
            click: () => {
              this.mainWindow.webContents.send('menu-cert-chain');
            }
          },
          {
            label: 'Cipher Suites',
            click: () => {
              this.mainWindow.webContents.send('menu-cipher-suites');
            }
          },
          {
            label: 'Settings',
            accelerator: 'CmdOrCtrl+,',
            click: () => {
              this.mainWindow.webContents.send('menu-settings');
            }
          }
        ]
      },
      {
        label: 'Help',
        submenu: [
          {
            label: 'Documentation',
            click: () => {
              shell.openExternal('https://docs.playnexus.com/ssl-tls-analyzer');
            }
          },
          {
            label: 'Support',
            click: () => {
              shell.openExternal('mailto:playnexushq@gmail.com?subject=SSL/TLS Analyzer Support');
            }
          },
          { type: 'separator' },
          {
            label: 'About',
            click: () => {
              this.showAbout();
            }
          }
        ]
      }
    ];

    const menu = Menu.buildFromTemplate(template);
    Menu.setApplicationMenu(menu);
  }

  setupIPC() {
    // Analyze SSL/TLS
    ipcMain.handle('analyze-ssl', async (event, hostname, port = 443) => {
      try {
        const analysis = await this.analyzeSSL(hostname, port);
        return {
          success: true,
          ...analysis,
          timestamp: new Date().toISOString()
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    });

    // Get certificate details
    ipcMain.handle('get-certificate', async (event, hostname, port = 443) => {
      try {
        const certificate = await this.getCertificateDetails(hostname, port);
        return {
          success: true,
          certificate: certificate,
          timestamp: new Date().toISOString()
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    });

    // Test cipher suites
    ipcMain.handle('test-cipher-suites', async (event, hostname, port = 443) => {
      try {
        const cipherSuites = await this.testCipherSuites(hostname, port);
        return {
          success: true,
          cipherSuites: cipherSuites,
          timestamp: new Date().toISOString()
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    });

    // Validate certificate chain
    ipcMain.handle('validate-cert-chain', async (event, hostname, port = 443) => {
      try {
        const validation = await this.validateCertificateChain(hostname, port);
        return {
          success: true,
          validation: validation,
          timestamp: new Date().toISOString()
        };
      } catch (error) {
        return {
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        };
      }
    });

    // Save settings
    ipcMain.handle('save-settings', async (event, settings) => {
      try {
        store.set('settings', settings);
        return { success: true };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });

    // Load settings
    ipcMain.handle('load-settings', async () => {
      try {
        const settings = store.get('settings', {
          timeout: 10000,
          checkRevocation: true,
          validateChain: true,
          checkWeakCiphers: true,
          theme: 'dark'
        });
        return { success: true, settings };
      } catch (error) {
        return { success: false, error: error.message };
      }
    });
  }

  async analyzeSSL(hostname, port = 443) {
    const analysis = {
      hostname: hostname,
      port: port,
      certificate: null,
      chain: [],
      protocols: [],
      cipherSuites: [],
      vulnerabilities: [],
      score: 0,
      grade: 'F',
      issues: [],
      recommendations: []
    };

    try {
      // Get certificate information using sslchecker
      const sslInfo = await sslChecker(hostname, { method: 'GET', port: port, protocol: 'https:' });
      
      // Get detailed certificate info
      const certDetails = await this.getCertificateDetails(hostname, port);
      analysis.certificate = certDetails;

      // Analyze certificate validity
      const now = new Date();
      const validFrom = new Date(sslInfo.validFrom);
      const validTo = new Date(sslInfo.validTo);

      analysis.certificate.validFrom = validFrom;
      analysis.certificate.validTo = validTo;
      analysis.certificate.daysUntilExpiry = sslInfo.daysRemaining;
      analysis.certificate.isExpired = now > validTo;
      analysis.certificate.isNotYetValid = now < validFrom;

      // Check for common vulnerabilities
      await this.checkVulnerabilities(analysis, hostname, port);

      // Test supported protocols
      analysis.protocols = await this.testProtocols(hostname, port);

      // Calculate security score
      this.calculateSecurityScore(analysis);

      return analysis;
    } catch (error) {
      throw new Error(`SSL analysis failed: ${error.message}`);
    }
  }

  async getCertificateDetails(hostname, port = 443) {
    return new Promise((resolve, reject) => {
      const options = {
        host: hostname,
        port: port,
        servername: hostname,
        rejectUnauthorized: false
      };

      const socket = tls.connect(options, () => {
        const certificate = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        socket.end();

        if (!certificate || Object.keys(certificate).length === 0) {
          reject(new Error('No certificate found'));
          return;
        }

        // Parse certificate details
        const certDetails = {
          subject: certificate.subject,
          issuer: certificate.issuer,
          serialNumber: certificate.serialNumber,
          fingerprint: certificate.fingerprint,
          fingerprint256: certificate.fingerprint256,
          validFrom: new Date(certificate.valid_from),
          validTo: new Date(certificate.valid_to),
          subjectAltNames: certificate.subjectaltname ? certificate.subjectaltname.split(', ') : [],
          keyUsage: certificate.ext_key_usage || [],
          basicConstraints: certificate.basic_constraints,
          signatureAlgorithm: certificate.sigalg,
          publicKeyAlgorithm: certificate.pubkey ? certificate.pubkey.type : 'Unknown',
          keySize: certificate.bits || 0,
          cipher: cipher,
          protocol: protocol,
          raw: certificate.raw
        };

        // Parse certificate chain
        let current = certificate;
        const chain = [];
        while (current) {
          chain.push({
            subject: current.subject,
            issuer: current.issuer,
            serialNumber: current.serialNumber,
            validFrom: new Date(current.valid_from),
            validTo: new Date(current.valid_to)
          });
          current = current.issuerCertificate;
          if (current && current.fingerprint === certificate.fingerprint) {
            break; // Prevent infinite loop
          }
        }
        certDetails.chain = chain;

        resolve(certDetails);
      });

      socket.on('error', (error) => {
        reject(new Error(`Connection failed: ${error.message}`));
      });

      socket.setTimeout(10000, () => {
        socket.destroy();
        reject(new Error('Connection timeout'));
      });
    });
  }

  async testProtocols(hostname, port = 443) {
    const protocols = ['TLSv1', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'];
    const supportedProtocols = [];

    for (const protocol of protocols) {
      try {
        const supported = await this.testProtocol(hostname, port, protocol);
        if (supported) {
          supportedProtocols.push({
            version: protocol,
            supported: true,
            secure: protocol === 'TLSv1.2' || protocol === 'TLSv1.3'
          });
        }
      } catch (error) {
        supportedProtocols.push({
          version: protocol,
          supported: false,
          secure: false,
          error: error.message
        });
      }
    }

    return supportedProtocols;
  }

  async testProtocol(hostname, port, protocol) {
    return new Promise((resolve) => {
      const options = {
        host: hostname,
        port: port,
        servername: hostname,
        secureProtocol: protocol + '_method',
        rejectUnauthorized: false
      };

      const socket = tls.connect(options, () => {
        socket.end();
        resolve(true);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.setTimeout(5000, () => {
        socket.destroy();
        resolve(false);
      });
    });
  }

  async testCipherSuites(hostname, port = 443) {
    // Common cipher suites to test
    const cipherSuites = [
      'ECDHE-RSA-AES256-GCM-SHA384',
      'ECDHE-RSA-AES128-GCM-SHA256',
      'ECDHE-RSA-AES256-SHA384',
      'ECDHE-RSA-AES128-SHA256',
      'DHE-RSA-AES256-GCM-SHA384',
      'DHE-RSA-AES128-GCM-SHA256',
      'AES256-GCM-SHA384',
      'AES128-GCM-SHA256',
      'RC4-SHA', // Weak cipher
      'DES-CBC-SHA', // Weak cipher
      'NULL-SHA' // Null cipher
    ];

    const results = [];

    for (const cipher of cipherSuites) {
      try {
        const supported = await this.testCipher(hostname, port, cipher);
        results.push({
          name: cipher,
          supported: supported,
          secure: this.isCipherSecure(cipher),
          strength: this.getCipherStrength(cipher)
        });
      } catch (error) {
        results.push({
          name: cipher,
          supported: false,
          secure: false,
          strength: 'unknown',
          error: error.message
        });
      }
    }

    return results;
  }

  async testCipher(hostname, port, cipher) {
    return new Promise((resolve) => {
      const options = {
        host: hostname,
        port: port,
        servername: hostname,
        ciphers: cipher,
        rejectUnauthorized: false
      };

      const socket = tls.connect(options, () => {
        socket.end();
        resolve(true);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.setTimeout(3000, () => {
        socket.destroy();
        resolve(false);
      });
    });
  }

  isCipherSecure(cipher) {
    const weakCiphers = ['RC4', 'DES', 'NULL', 'EXPORT', 'MD5'];
    return !weakCiphers.some(weak => cipher.includes(weak));
  }

  getCipherStrength(cipher) {
    if (cipher.includes('256')) return 'high';
    if (cipher.includes('128')) return 'medium';
    if (cipher.includes('RC4') || cipher.includes('DES')) return 'weak';
    if (cipher.includes('NULL')) return 'none';
    return 'unknown';
  }

  async validateCertificateChain(hostname, port = 443) {
    try {
      const certDetails = await this.getCertificateDetails(hostname, port);
      const validation = {
        valid: true,
        issues: [],
        chain: certDetails.chain,
        trustPath: []
      };

      // Check certificate expiry
      const now = new Date();
      if (certDetails.validTo < now) {
        validation.valid = false;
        validation.issues.push('Certificate has expired');
      }

      if (certDetails.validFrom > now) {
        validation.valid = false;
        validation.issues.push('Certificate is not yet valid');
      }

      // Check certificate chain
      if (certDetails.chain.length < 2) {
        validation.issues.push('Incomplete certificate chain');
      }

      // Check for self-signed certificate
      const rootCert = certDetails.chain[certDetails.chain.length - 1];
      if (rootCert && rootCert.subject.CN === rootCert.issuer.CN) {
        validation.issues.push('Self-signed certificate detected');
      }

      // Check hostname matching
      const subjectAltNames = certDetails.subjectAltNames || [];
      const commonName = certDetails.subject.CN;
      
      const hostnameMatches = subjectAltNames.some(name => 
        name.replace('DNS:', '') === hostname || 
        name.replace('DNS:', '').startsWith('*.')
      ) || commonName === hostname || commonName.startsWith('*.');

      if (!hostnameMatches) {
        validation.valid = false;
        validation.issues.push('Hostname does not match certificate');
      }

      return validation;
    } catch (error) {
      return {
        valid: false,
        issues: [`Validation failed: ${error.message}`],
        chain: [],
        trustPath: []
      };
    }
  }

  async checkVulnerabilities(analysis, hostname, port) {
    const vulnerabilities = [];

    // Check for weak protocols
    const weakProtocols = analysis.protocols.filter(p => 
      p.supported && (p.version === 'TLSv1' || p.version === 'TLSv1.1')
    );
    
    if (weakProtocols.length > 0) {
      vulnerabilities.push({
        type: 'weak_protocol',
        severity: 'medium',
        description: 'Weak TLS protocols supported',
        protocols: weakProtocols.map(p => p.version)
      });
    }

    // Check certificate expiry
    if (analysis.certificate && analysis.certificate.daysUntilExpiry < 30) {
      vulnerabilities.push({
        type: 'expiring_certificate',
        severity: analysis.certificate.daysUntilExpiry < 7 ? 'high' : 'medium',
        description: `Certificate expires in ${analysis.certificate.daysUntilExpiry} days`
      });
    }

    // Check key size
    if (analysis.certificate && analysis.certificate.keySize < 2048) {
      vulnerabilities.push({
        type: 'weak_key',
        severity: 'high',
        description: `Weak key size: ${analysis.certificate.keySize} bits`
      });
    }

    // Check signature algorithm
    if (analysis.certificate && analysis.certificate.signatureAlgorithm.includes('SHA1')) {
      vulnerabilities.push({
        type: 'weak_signature',
        severity: 'medium',
        description: 'Weak signature algorithm: SHA1'
      });
    }

    analysis.vulnerabilities = vulnerabilities;
  }

  calculateSecurityScore(analysis) {
    let score = 100;
    const issues = [];
    const recommendations = [];

    // Deduct points for vulnerabilities
    analysis.vulnerabilities.forEach(vuln => {
      switch (vuln.severity) {
        case 'high':
          score -= 25;
          break;
        case 'medium':
          score -= 15;
          break;
        case 'low':
          score -= 5;
          break;
      }
      issues.push(vuln.description);
    });

    // Check for weak protocols
    const hasWeakProtocols = analysis.protocols.some(p => 
      p.supported && !p.secure
    );
    if (hasWeakProtocols) {
      score -= 20;
      issues.push('Weak TLS protocols supported');
      recommendations.push('Disable TLS 1.0 and 1.1');
    }

    // Check for strong protocols
    const hasStrongProtocols = analysis.protocols.some(p => 
      p.supported && p.version === 'TLSv1.3'
    );
    if (!hasStrongProtocols) {
      score -= 10;
      recommendations.push('Enable TLS 1.3 for better security');
    }

    // Certificate validation
    if (analysis.certificate) {
      if (analysis.certificate.keySize >= 4096) {
        score += 5; // Bonus for strong key
      } else if (analysis.certificate.keySize < 2048) {
        score -= 30;
        issues.push('Weak RSA key size');
        recommendations.push('Use at least 2048-bit RSA keys');
      }

      if (analysis.certificate.signatureAlgorithm.includes('SHA256') || 
          analysis.certificate.signatureAlgorithm.includes('SHA384')) {
        score += 5; // Bonus for strong signature
      }
    }

    // Ensure score doesn't go below 0
    score = Math.max(0, score);

    // Assign grade
    if (score >= 90) analysis.grade = 'A+';
    else if (score >= 80) analysis.grade = 'A';
    else if (score >= 70) analysis.grade = 'B';
    else if (score >= 60) analysis.grade = 'C';
    else if (score >= 50) analysis.grade = 'D';
    else analysis.grade = 'F';

    analysis.score = score;
    analysis.issues = issues;
    analysis.recommendations = recommendations;
  }

  async exportCertificate() {
    const { filePath } = await dialog.showSaveDialog(this.mainWindow, {
      defaultPath: `certificate-${new Date().toISOString().split('T')[0]}.pem`,
      filters: [
        { name: 'PEM Files', extensions: ['pem'] },
        { name: 'DER Files', extensions: ['der'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    });

    if (filePath) {
      this.mainWindow.webContents.send('export-certificate', filePath);
    }
  }

  showAbout() {
    dialog.showMessageBox(this.mainWindow, {
      type: 'info',
      title: 'About PlayNexus SSL/TLS Analyzer',
      message: 'PlayNexus SSL/TLS Analyzer v1.0.0',
      detail: 'Powered by PlayNexus — Subsystems: ClanForge, BotForge.\nOwned by Nortaq.\nContact: playnexushq@gmail.com\n\nProfessional SSL/TLS certificate analysis and security validation tool for ethical security testing.'
    });
  }
}

// Initialize app
new SSLTLSAnalyzer();

// Auto-updater events
autoUpdater.on('checking-for-update', () => {
  console.log('Checking for update...');
});

autoUpdater.on('update-available', (info) => {
  console.log('Update available.');
});

autoUpdater.on('update-not-available', (info) => {
  console.log('Update not available.');
});

autoUpdater.on('error', (err) => {
  console.log('Error in auto-updater. ' + err);
});

autoUpdater.on('download-progress', (progressObj) => {
  let log_message = "Download speed: " + progressObj.bytesPerSecond;
  log_message = log_message + ' - Downloaded ' + progressObj.percent + '%';
  log_message = log_message + ' (' + progressObj.transferred + "/" + progressObj.total + ')';
  console.log(log_message);
});

autoUpdater.on('update-downloaded', (info) => {
  console.log('Update downloaded');
  autoUpdater.quitAndInstall();
});
