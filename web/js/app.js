/**
 * Distriblog Web Client
 * Single-file version (no ES modules for browser compatibility)
 */

(function() {
  'use strict';

  // ============================================
  // CRYPTO MODULE
  // ============================================

  function encodeHex(bytes) {
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function decodeHex(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function canonicalize(obj) {
    // Sort keys and create compact JSON (no whitespace in structure)
    // Note: JSON.stringify with sorted replacer produces compact output
    const sortedKeys = Object.keys(obj).sort();
    const sorted = {};
    for (const key of sortedKeys) {
      if (obj[key] !== undefined) {
        sorted[key] = obj[key];
      }
    }
    // No .replace() - that would corrupt spaces inside string values!
    return JSON.stringify(sorted);
  }

  async function sha256(data) {
    const encoder = new TextEncoder();
    const bytes = typeof data === 'string' ? encoder.encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    return encodeHex(new Uint8Array(hashBuffer));
  }

  const Crypto = {
    generateKeyPair() {
      const signKp = nacl.sign.keyPair();
      const encKp = nacl.box.keyPair();
      return {
        signing: {
          publicKey: encodeHex(signKp.publicKey),
          secretKey: encodeHex(signKp.secretKey),
        },
        encryption: {
          publicKey: encodeHex(encKp.publicKey),
          secretKey: encodeHex(encKp.secretKey),
        },
      };
    },

    sign(message, secretKeyHex) {
      const secretKey = decodeHex(secretKeyHex);
      const messageBytes = new TextEncoder().encode(message);
      const signature = nacl.sign.detached(messageBytes, secretKey);
      return encodeHex(signature);
    },

    verify(message, signatureHex, publicKeyHex) {
      const publicKey = decodeHex(publicKeyHex);
      const signature = decodeHex(signatureHex);
      const messageBytes = new TextEncoder().encode(message);
      return nacl.sign.detached.verify(messageBytes, signature, publicKey);
    },

    // Encryption parameters (must match Python ENCRYPTION_V1)
    ENCRYPTION_V1: {
      version: 1,
      kdf: 'pbkdf2-sha256',
      kdf_iterations: 100000,
      cipher: 'aes-256-gcm',
    },

    async encryptWithPassword(data, password) {
      const encoder = new TextEncoder();
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));

      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: this.ENCRYPTION_V1.kdf_iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );

      const dataBytes = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, dataBytes);

      // Return explicit format with all parameters
      return {
        v: this.ENCRYPTION_V1.version,
        kdf: this.ENCRYPTION_V1.kdf,
        kdf_iterations: this.ENCRYPTION_V1.kdf_iterations,
        cipher: this.ENCRYPTION_V1.cipher,
        salt: encodeHex(salt),
        iv: encodeHex(iv),
        ciphertext: encodeHex(new Uint8Array(ciphertext)),
      };
    },

    async decryptWithPassword(encrypted, password) {
      const encoder = new TextEncoder();

      if (encrypted.v !== 1) {
        throw new Error(`Unsupported encryption version: ${encrypted.v}`);
      }

      const salt = decodeHex(encrypted.salt);
      const iv = decodeHex(encrypted.iv);
      const ciphertext = decodeHex(encrypted.ciphertext);
      const iterations = encrypted.kdf_iterations;

      const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    },
  };

  // ============================================
  // STORAGE MODULE
  // ============================================

  const STORAGE_KEYS = {
    IDENTITIES: 'distriblog_identities',
    ACTIVE_IDENTITY: 'distriblog_active_identity',
    SETTINGS: 'distriblog_settings',
  };

  const StorageMethod = { PASSWORD: 'password', WEBAUTHN: 'webauthn' };

  const KeyStore = {
    listIdentities() {
      const data = localStorage.getItem(STORAGE_KEYS.IDENTITIES);
      if (!data) return [];
      try { return JSON.parse(data); } catch { return []; }
    },

    getIdentity(identityHash) {
      return this.listIdentities().find(i => i.identityHash === identityHash) || null;
    },

    getActiveIdentity() {
      return localStorage.getItem(STORAGE_KEYS.ACTIVE_IDENTITY);
    },

    setActiveIdentity(identityHash) {
      if (identityHash) {
        localStorage.setItem(STORAGE_KEYS.ACTIVE_IDENTITY, identityHash);
      } else {
        localStorage.removeItem(STORAGE_KEYS.ACTIVE_IDENTITY);
      }
    },

    async createIdentityWithPassword(name, password) {
      const keyPair = Crypto.generateKeyPair();
      const identityHash = await sha256(keyPair.signing.publicKey);
      const encryptedKeys = await Crypto.encryptWithPassword(keyPair, password);

      const identity = {
        identityHash,
        name: name || '',
        createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys,
        signingPubkey: keyPair.signing.publicKey,
        encryptionPubkey: keyPair.encryption.publicKey,
      };

      this._saveIdentity(identity);
      return { identity, keyPair };
    },

    async unlockIdentity(identityHash, password) {
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');

      if (identity.storageMethod === StorageMethod.PASSWORD) {
        try {
          return await Crypto.decryptWithPassword(identity.encryptedKeys, password);
        } catch {
          throw new Error('Invalid password');
        }
      }
      throw new Error('Unknown storage method');
    },

    deleteIdentity(identityHash) {
      const identities = this.listIdentities().filter(i => i.identityHash !== identityHash);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
      if (this.getActiveIdentity() === identityHash) {
        this.setActiveIdentity(null);
      }
    },

    _saveIdentity(identity) {
      const identities = this.listIdentities();
      identities.push(identity);
      localStorage.setItem(STORAGE_KEYS.IDENTITIES, JSON.stringify(identities));
    },

    async dumpIdentity(identityHash, password) {
      /**
       * Create a portable dump of an identity with encrypted private keys.
       * Format is compatible with CLI 'identity restore' command.
       */
      const identity = this.getIdentity(identityHash);
      if (!identity) throw new Error('Identity not found');

      // Get decrypted keys (need to unlock first)
      const keyPair = SessionKeys.get(identityHash);
      if (!keyPair) throw new Error('Identity must be unlocked to dump');

      // Fetch sigchain from API
      let sigchain = [];
      try {
        const response = await api.request('GET', `/identities/${identityHash}/sigchain`);
        sigchain = response.events || [];
      } catch (e) {
        console.warn('Could not fetch sigchain from API, using empty:', e);
      }

      // Encrypt keys for dump (format compatible with CLI)
      const keysJson = JSON.stringify({
        signing_key: keyPair.signing.secretKey,
        encryption_key: keyPair.encryption.secretKey,
      });
      const encryptedKeys = await Crypto.encryptWithPassword(keysJson, password);

      // Create dump
      return {
        version: 1,
        format: 'distriblog-identity-dump',
        identity_hash: identityHash,
        sigchain: sigchain,
        encrypted_keys: encryptedKeys,
      };
    },

    async restoreIdentity(dump, password, localPassword) {
      /**
       * Restore an identity from a dump file.
       * @param dump - The dump object
       * @param password - Password used to encrypt the dump
       * @param localPassword - Password to use for local storage
       */
      if (dump.format !== 'distriblog-identity-dump') {
        throw new Error('Invalid dump format');
      }

      // Decrypt keys from dump
      let keysData;
      try {
        keysData = await Crypto.decryptWithPassword(dump.encrypted_keys, password);
      } catch (e) {
        throw new Error('Invalid password');
      }

      // Re-encrypt for local storage
      const encryptedKeys = await Crypto.encryptWithPassword(keysData, localPassword);

      // Parse keys to get public keys
      const keys = typeof keysData === 'string' ? JSON.parse(keysData) : keysData;

      // Derive public keys from secret keys using nacl
      const signingSecretKey = decodeHex(keys.signing_key);
      const signingKeyPair = nacl.sign.keyPair.fromSecretKey(signingSecretKey);
      const signingPubkey = encodeHex(signingKeyPair.publicKey);

      const encryptionSecretKey = decodeHex(keys.encryption_key);
      const encryptionKeyPair = nacl.box.keyPair.fromSecretKey(encryptionSecretKey);
      const encryptionPubkey = encodeHex(encryptionKeyPair.publicKey);

      // Create identity for localStorage
      const identity = {
        identityHash: dump.identity_hash,
        name: dump.sigchain?.[0]?.name || '',
        createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys,
        signingPubkey,
        encryptionPubkey,
      };

      // Check if identity already exists
      if (this.getIdentity(dump.identity_hash)) {
        throw new Error('Identity already exists');
      }

      this._saveIdentity(identity);

      // Register sigchain with API if we have events
      if (dump.sigchain && dump.sigchain.length > 0) {
        try {
          // Try to create identity on server (may already exist)
          await api.request('POST', '/identities', { event: dump.sigchain[0] });
        } catch (e) {
          console.warn('Could not register identity with API:', e);
        }
      }

      return identity;
    },
  };

  const SessionKeys = {
    _keys: new Map(),
    set(identityHash, keyPair) { this._keys.set(identityHash, keyPair); },
    get(identityHash) { return this._keys.get(identityHash) || null; },
    isUnlocked(identityHash) { return this._keys.has(identityHash); },
    lock(identityHash) { this._keys.delete(identityHash); },
    lockAll() { this._keys.clear(); },
  };

  const Settings = {
    getAll() {
      const data = localStorage.getItem(STORAGE_KEYS.SETTINGS);
      try { return data ? JSON.parse(data) : {}; } catch { return {}; }
    },
    get(key, defaultValue) {
      const settings = this.getAll();
      return key in settings ? settings[key] : defaultValue;
    },
    set(key, value) {
      const settings = this.getAll();
      settings[key] = value;
      localStorage.setItem(STORAGE_KEYS.SETTINGS, JSON.stringify(settings));
    },
  };

  // ============================================
  // API CLIENT
  // ============================================

  const api = {
    baseUrl: '/api',
    sessionToken: null,

    setSession(token) { this.sessionToken = token; },
    clearSession() { this.sessionToken = null; },

    async request(method, path, body) {
      const headers = { 'Content-Type': 'application/json' };
      if (this.sessionToken) headers['Authorization'] = `Bearer ${this.sessionToken}`;

      const options = { method, headers };
      if (body) options.body = JSON.stringify(body);

      const response = await fetch(`${this.baseUrl}${path}`, options);
      if (!response.ok) {
        const error = await response.json().catch(() => ({ error: 'Unknown error' }));
        const err = new Error(error.error || error.message || 'Request failed');
        err.status = response.status;
        throw err;
      }
      return response.json();
    },

    async createIdentity(keyPair, name) {
      const timestamp = Math.floor(Date.now() / 1000);
      const event = {
        // Base SigchainEvent fields
        version: 1,
        type: 'genesis',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: null,
        signed_by: keyPair.signing.publicKey,
        // GenesisEvent fields
        pubkey: keyPair.signing.publicKey,
        encryption_pubkey: keyPair.encryption.publicKey,
        identity_type: 'personal',
        name: name || null,
        ephemeral: false,
        ownership_proof: null,
      };
      const signable = canonicalize(event);
      event.signature = Crypto.sign(signable, keyPair.signing.secretKey);
      return this.request('POST', '/identities', { event });
    },

    async getIdentity(identityHash) {
      return this.request('GET', `/identities/${identityHash}`);
    },

    async createSession(identityHash, keyPair, expiresIn = 3600) {
      const timestamp = Math.floor(Date.now() / 1000);
      const request = {
        identity: identityHash,
        device_pubkey: keyPair.signing.publicKey,
        timestamp,
        expires_in: expiresIn,
      };
      request.signature = Crypto.sign(canonicalize(request), keyPair.signing.secretKey);
      const result = await this.request('POST', '/session', request);
      this.sessionToken = result.token;
      return result;
    },

    async getTrustAssertions(identityHash) {
      return this.request('GET', `/trust/assertions?target=${identityHash}`);
    },
  };

  // ============================================
  // QR CODE
  // ============================================

  function createIdentityQR(identityHash) {
    return `distriblog:id:${identityHash}`;
  }

  // ============================================
  // ALPINE.JS INITIALIZATION
  // ============================================

  document.addEventListener('alpine:init', () => {
    // Global app state
    Alpine.store('app', {
      initialized: false,
      online: navigator.onLine,
      currentView: 'identities',
      loading: false,
      error: null,
      success: null,

      init() {
        this.initialized = true;
        window.addEventListener('online', () => this.online = true);
        window.addEventListener('offline', () => this.online = false);
      },

      setView(view) {
        this.currentView = view;
        this.error = null;
        this.success = null;
      },

      showError(message) {
        this.error = message;
        setTimeout(() => this.error = null, 5000);
      },

      showSuccess(message) {
        this.success = message;
        setTimeout(() => this.success = null, 3000);
      },
    });

    // Shared identity state (reactive across all components)
    Alpine.store('identity', {
      identities: [],
      activeIdentity: null,
      activeHash: null,

      init() {
        this.reload();
      },

      reload() {
        this.identities = KeyStore.listIdentities();
        this.activeHash = KeyStore.getActiveIdentity();
        if (this.activeHash) {
          this.activeIdentity = this.identities.find(i => i.identityHash === this.activeHash) || null;
        } else {
          this.activeIdentity = null;
        }
      },

      setActive(identityHash) {
        KeyStore.setActiveIdentity(identityHash);
        this.reload();
      },

      isUnlocked(identityHash) {
        return SessionKeys.isUnlocked(identityHash);
      },
    });

    // Identity manager
    Alpine.data('identityManager', () => ({
      showCreateModal: false,
      showUnlockModal: false,
      unlockingIdentity: null,
      createForm: { name: '', method: 'password', password: '', confirmPassword: '' },
      unlockPassword: '',

      // Use store for shared state
      get identities() { return Alpine.store('identity').identities; },
      get activeIdentity() { return Alpine.store('identity').activeIdentity; },

      init() {
        // Reload store on init to ensure fresh data
        Alpine.store('identity').reload();
      },

      get webauthnSupported() { return false; }, // Simplified - disabled for now

      async createIdentity() {
        const { name, method, password, confirmPassword } = this.createForm;

        if (method === 'password') {
          if (!password || password.length < 8) {
            Alpine.store('app').showError('Password must be at least 8 characters');
            return;
          }
          if (password !== confirmPassword) {
            Alpine.store('app').showError('Passwords do not match');
            return;
          }
        }

        Alpine.store('app').loading = true;

        try {
          const result = await KeyStore.createIdentityWithPassword(name, password);

          try {
            await api.createIdentity(result.keyPair, name);
          } catch (e) {
            console.warn('Failed to register identity with API:', e);
          }

          SessionKeys.set(result.identity.identityHash, result.keyPair);
          Alpine.store('identity').setActive(result.identity.identityHash);

          this.showCreateModal = false;
          this.createForm = { name: '', method: 'password', password: '', confirmPassword: '' };

          Alpine.store('app').showSuccess('Identity created successfully');
        } catch (e) {
          Alpine.store('app').showError(e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      openUnlock(identity) {
        this.unlockingIdentity = identity;
        this.unlockPassword = '';
        this.showUnlockModal = true;
      },

      async unlockIdentity() {
        if (!this.unlockingIdentity) return;

        Alpine.store('app').loading = true;

        try {
          const keyPair = await KeyStore.unlockIdentity(
            this.unlockingIdentity.identityHash,
            this.unlockPassword
          );

          SessionKeys.set(this.unlockingIdentity.identityHash, keyPair);
          Alpine.store('identity').setActive(this.unlockingIdentity.identityHash);

          try {
            await api.createSession(this.unlockingIdentity.identityHash, keyPair);
          } catch (e) {
            console.warn('Failed to create API session:', e);
          }

          this.showUnlockModal = false;
          this.unlockingIdentity = null;

          Alpine.store('app').showSuccess('Identity unlocked');
        } catch (e) {
          Alpine.store('app').showError(e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      isUnlocked(identityHash) { return SessionKeys.isUnlocked(identityHash); },

      lockIdentity(identityHash) {
        SessionKeys.lock(identityHash);
        if (KeyStore.getActiveIdentity() === identityHash) api.clearSession();
        Alpine.store('identity').reload();
      },

      setActive(identityHash) {
        Alpine.store('identity').setActive(identityHash);
      },

      deleteIdentity(identityHash) {
        if (!confirm('Are you sure you want to delete this identity?')) return;
        KeyStore.deleteIdentity(identityHash);
        SessionKeys.lock(identityHash);
        Alpine.store('identity').reload();
        Alpine.store('app').showSuccess('Identity deleted');
      },

      formatDate(timestamp) { return new Date(timestamp).toLocaleString(); },
      truncateHash(hash) { return hash ? hash.slice(0, 8) + '...' + hash.slice(-8) : ''; },
    }));

    // Identity detail
    Alpine.data('identityDetail', () => ({
      sigchain: [],
      devices: [],
      recovery: null,
      loading: false,
      lastLoadedHash: null,

      // Use store for identity
      get identity() { return Alpine.store('identity').activeIdentity; },

      init() {
        // Watch for view changes to reload when becoming visible
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'identity') {
            this.load();
          }
        });
        // Also watch for active identity changes
        this.$watch('$store.identity.activeHash', () => {
          if (Alpine.store('app').currentView === 'identity') {
            this.load();
          }
        });
        // Initial load if we're on this view
        if (Alpine.store('app').currentView === 'identity') {
          this.load();
        }
      },

      async load() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          return;
        }

        // Skip if already loaded this hash
        if (this.lastLoadedHash === activeHash && this.sigchain.length > 0) {
          return;
        }

        this.loading = true;
        this.lastLoadedHash = activeHash;

        try {
          const data = await api.getIdentity(activeHash);
          this.sigchain = data.sigchain || [];
          this.devices = data.devices || [];
          this.recovery = data.recovery || null;
        } catch (e) {
          console.warn('Failed to load identity from API:', e);
          this.sigchain = [];
          this.devices = [];
          this.recovery = null;
        } finally {
          this.loading = false;
        }
      },

      get activeDevices() { return this.devices; },
    }));

    // QR manager
    Alpine.data('qrManager', () => ({
      identityHash: null,
      scanning: false,

      async showIdentityQR(identityHash) {
        if (!identityHash) return;
        this.identityHash = identityHash;

        await this.$nextTick();
        const container = this.$refs.qrContainer;
        if (container && typeof QRCode !== 'undefined') {
          container.innerHTML = '';
          const canvas = document.createElement('canvas');
          container.appendChild(canvas);
          QRCode.toCanvas(canvas, createIdentityQR(identityHash), {
            width: 200,
            margin: 2,
            color: { dark: '#1a1a2e', light: '#ffffff' },
          });
        }
      },

      async copyIdentityHash() {
        if (!this.identityHash) return;
        try {
          await navigator.clipboard.writeText(this.identityHash);
          Alpine.store('app').showSuccess('Copied to clipboard');
        } catch {
          Alpine.store('app').showError('Failed to copy');
        }
      },

      startScan() { Alpine.store('app').showError('QR scanning not yet implemented'); },
      stopScan() { this.scanning = false; },
    }));

    // Trust manager
    Alpine.data('trustManager', () => ({
      targetIdentity: '',
      assertions: [],
      delegations: [],
      loading: false,
      assertForm: { name: '', confidence: 1.0 },
      delegateForm: { weight: 0.5, scope: 'identity' },

      async lookup() {
        if (!this.targetIdentity) return;
        this.loading = true;
        try {
          const data = await api.getTrustAssertions(this.targetIdentity);
          this.assertions = data.identity_assertions || [];
          this.delegations = data.delegations || [];
        } catch (e) {
          Alpine.store('app').showError('Failed to load trust data');
        } finally {
          this.loading = false;
        }
      },

      assertName() { Alpine.store('app').showError('Not yet implemented'); },
      delegate() { Alpine.store('app').showError('Not yet implemented'); },
    }));

    // Settings manager
    Alpine.data('settingsManager', () => ({
      apiUrl: '/api',
      autoLock: 5,
      showDumpModal: false,
      showRestoreModal: false,
      dumpPassword: '',
      dumpConfirmPassword: '',
      restorePassword: '',
      restoreLocalPassword: '',
      restoreLocalConfirmPassword: '',
      restoreFile: null,

      init() {
        this.apiUrl = Settings.get('apiUrl', '/api');
        this.autoLock = Settings.get('autoLock', 5);
      },

      save() {
        Settings.set('apiUrl', this.apiUrl);
        Settings.set('autoLock', this.autoLock);
        api.baseUrl = this.apiUrl;
        Alpine.store('app').showSuccess('Settings saved');
      },

      exportData() {
        const identities = KeyStore.listIdentities();
        const data = { version: 1, exportedAt: new Date().toISOString(), identities };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `distriblog-backup-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
      },

      async importData(event) {
        const file = event.target.files[0];
        if (!file) return;
        try {
          const text = await file.text();
          const data = JSON.parse(text);
          if (data.version !== 1) throw new Error('Unsupported version');
          let imported = 0;
          for (const identity of data.identities) {
            if (!KeyStore.getIdentity(identity.identityHash)) {
              KeyStore._saveIdentity(identity);
              imported++;
            }
          }
          Alpine.store('app').showSuccess(`Imported ${imported} identities`);
        } catch (e) {
          Alpine.store('app').showError('Import failed: ' + e.message);
        }
      },

      openDumpModal() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          Alpine.store('app').showError('No active identity');
          return;
        }
        if (!SessionKeys.isUnlocked(activeHash)) {
          Alpine.store('app').showError('Identity must be unlocked first');
          return;
        }
        this.dumpPassword = '';
        this.dumpConfirmPassword = '';
        this.showDumpModal = true;
      },

      async dumpIdentity() {
        if (this.dumpPassword.length < 8) {
          Alpine.store('app').showError('Password must be at least 8 characters');
          return;
        }
        if (this.dumpPassword !== this.dumpConfirmPassword) {
          Alpine.store('app').showError('Passwords do not match');
          return;
        }

        const activeHash = Alpine.store('identity').activeHash;
        Alpine.store('app').loading = true;

        try {
          const dump = await KeyStore.dumpIdentity(activeHash, this.dumpPassword);
          const blob = new Blob([JSON.stringify(dump, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `identity-${activeHash.slice(0, 8)}-${Date.now()}.json`;
          a.click();
          URL.revokeObjectURL(url);

          this.showDumpModal = false;
          Alpine.store('app').showSuccess('Identity dumped successfully');
        } catch (e) {
          Alpine.store('app').showError('Dump failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      openRestoreModal() {
        this.restorePassword = '';
        this.restoreLocalPassword = '';
        this.restoreLocalConfirmPassword = '';
        this.restoreFile = null;
        this.showRestoreModal = true;
      },

      handleRestoreFile(event) {
        this.restoreFile = event.target.files[0];
      },

      async restoreIdentity() {
        if (!this.restoreFile) {
          Alpine.store('app').showError('Please select a dump file');
          return;
        }
        if (!this.restorePassword) {
          Alpine.store('app').showError('Please enter the dump password');
          return;
        }
        if (this.restoreLocalPassword.length < 8) {
          Alpine.store('app').showError('Local password must be at least 8 characters');
          return;
        }
        if (this.restoreLocalPassword !== this.restoreLocalConfirmPassword) {
          Alpine.store('app').showError('Local passwords do not match');
          return;
        }

        Alpine.store('app').loading = true;

        try {
          const text = await this.restoreFile.text();
          const dump = JSON.parse(text);

          await KeyStore.restoreIdentity(dump, this.restorePassword, this.restoreLocalPassword);

          Alpine.store('identity').reload();
          this.showRestoreModal = false;
          Alpine.store('app').showSuccess('Identity restored successfully');
        } catch (e) {
          Alpine.store('app').showError('Restore failed: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },
    }));
  });

  // Register service worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', async () => {
      try {
        await navigator.serviceWorker.register('/sw.js');
      } catch (e) {
        console.warn('ServiceWorker registration failed:', e);
      }
    });
  }

})();
