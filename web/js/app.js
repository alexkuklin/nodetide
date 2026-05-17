/**
 * Nodetide Web Client
 * Single-file version (no ES modules for browser compatibility)
 */

(function() {
  'use strict';

  // Version injected at build time (replaced by Dockerfile)
  const WEB_VERSION = '__GIT_COMMIT__';

  // Set version info immediately (independent of Alpine)
  window.NODETIDE_VERSION = {
    web: (typeof WEB_VERSION === 'string' && !WEB_VERSION.startsWith('__')) ? WEB_VERSION.slice(0, 7) : 'dev',
    api: null
  };

  // Fetch API version immediately
  fetch('/health')
    .then(r => r.json())
    .then(data => {
      window.NODETIDE_VERSION.api = data.commit?.slice(0, 7) || 'unknown';
      updateVersionDisplay();
    })
    .catch(() => {
      window.NODETIDE_VERSION.api = 'offline';
      updateVersionDisplay();
    });

  function updateVersionDisplay() {
    const el = document.getElementById('version-display');
    if (el) {
      el.textContent = `(web:${window.NODETIDE_VERSION.web} api:${window.NODETIDE_VERSION.api || '...'})`;
    }
  }

  // Update on page show (handles bfcache)
  window.addEventListener('pageshow', updateVersionDisplay);

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
    // Recursively sort keys and create compact JSON (no whitespace in structure)
    function sortRecursive(val) {
      if (val === null || typeof val !== 'object') {
        return val;
      }
      if (Array.isArray(val)) {
        return val.map(sortRecursive);
      }
      const sortedKeys = Object.keys(val).sort();
      const sorted = {};
      for (const key of sortedKeys) {
        if (val[key] !== undefined) {
          sorted[key] = sortRecursive(val[key]);
        }
      }
      return sorted;
    }
    return JSON.stringify(sortRecursive(obj));
  }

  async function sha256(data) {
    console.log('[sha256] called with:', typeof data, data?.length || data);
    if (!crypto || !crypto.subtle) {
      console.error('[sha256] crypto.subtle not available. Secure context:', window.isSecureContext);
      throw new Error('Web Crypto API not available. HTTPS required.');
    }
    const encoder = new TextEncoder();
    const bytes = typeof data === 'string' ? encoder.encode(data) : data;
    console.log('[sha256] hashing bytes:', bytes.length);
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const result = encodeHex(new Uint8Array(hashBuffer));
    console.log('[sha256] result:', result.slice(0, 16) + '...');
    return result;
  }

  // Sigchain helpers (consumer-side interpretation)
  const SigchainUtils = {
    /**
     * Get the latest value of a field from sigchain events.
     * Iterates through all events and returns the last non-null value found.
     */
    getLatestField(events, fieldName, defaultValue = null) {
      let value = defaultValue;
      for (const event of events) {
        if (event[fieldName] !== undefined && event[fieldName] !== null) {
          value = event[fieldName];
        }
      }
      return value;
    },
  };

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

    async sha256Hex(data) {
      return sha256(data);
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
    IDENTITIES: 'nodetide_identities',
    ACTIVE_IDENTITY: 'nodetide_active_identity',
    SETTINGS: 'nodetide_settings',
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

    async createIdentityWithPassword(name, password, distributionPoints = null) {
      console.log('[createIdentityWithPassword] starting, name:', name);
      const keyPair = Crypto.generateKeyPair();
      console.log('[createIdentityWithPassword] keyPair generated');

      // Create genesis event to compute identity hash (must match server computation)
      const timestamp = Math.floor(Date.now() / 1000);
      const genesisEvent = {
        version: 1,
        type: 'genesis',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: null,
        signed_by: keyPair.signing.publicKey,
        pubkey: keyPair.signing.publicKey,
        encryption_pubkey: keyPair.encryption.publicKey,
        identity_type: 'personal',
        name: name || null,
        ephemeral: false,
        ownership_proof: null,
        distribution_points: distributionPoints,
      };
      const signable = canonicalize(genesisEvent);
      genesisEvent.signature = Crypto.sign(signable, keyPair.signing.secretKey);

      // Identity hash = hash of the complete signed genesis event
      const identityHash = await sha256(canonicalize(genesisEvent));
      console.log('[createIdentityWithPassword] identityHash:', identityHash.slice(0, 16) + '...');

      const encryptedKeys = await Crypto.encryptWithPassword(keyPair, password);

      const identity = {
        identityHash,
        name: name || '',
        createdAt: Date.now(),
        storageMethod: StorageMethod.PASSWORD,
        encryptedKeys,
        signingPubkey: keyPair.signing.publicKey,
        encryptionPubkey: keyPair.encryption.publicKey,
        distributionPoints: distributionPoints,
        genesisEvent, // Store for later sync
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
        format: 'nodetide-identity-dump',
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
      if (dump.format !== 'nodetide-identity-dump') {
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

    async createIdentity(keyPair, name, distributionPoints = null) {
      console.log('[api.createIdentity] called with distributionPoints:', distributionPoints);
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
        distribution_points: distributionPoints,
      };
      console.log('[api.createIdentity] event.distribution_points:', event.distribution_points);
      const signable = canonicalize(event);
      event.signature = Crypto.sign(signable, keyPair.signing.secretKey);
      console.log('[api.createIdentity] sending event to API...');
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

    async listServerIdentities() {
      return this.request('GET', '/identities');
    },

    async submitGenesisEvent(event) {
      return this.request('POST', '/identities', { event });
    },

    async publishMessage(message) {
      return this.request('POST', '/messages', { message });
    },

    async listMessages(sender = null, limit = 50) {
      const params = new URLSearchParams();
      if (sender) params.set('sender', sender);
      params.set('limit', limit);
      return this.request('GET', `/messages?${params}`);
    },

    async getTrustAssertions(identityHash) {
      return this.request('GET', `/trust/assertions?target=${identityHash}`);
    },

    async submitEvent(identityHash, event) {
      return this.request('POST', `/identities/${identityHash}/events`, { event });
    },

    createSetDistributionEvent(keyPair, prevHash, distributionPoints) {
      const timestamp = Math.floor(Date.now() / 1000);
      const event = {
        version: 1,
        type: 'set_distribution',
        alg: 'ed25519',
        hash_alg: 'sha256',
        timestamp,
        prev: prevHash,
        signed_by: keyPair.signing.publicKey,
        distribution_points: distributionPoints,
      };
      // Sign the event
      const signable = canonicalize(event);
      event.signature = Crypto.sign(signable, keyPair.signing.secretKey);
      return event;
    },
  };

  // ============================================
  // QR CODE
  // ============================================

  function createIdentityQR(identityHash, distributionPoints = [], signingKey = null) {
    // Create a compact JSON payload with identity info
    const payload = {
      v: 1,  // version
      id: identityHash,
    };
    if (distributionPoints && distributionPoints.length > 0) {
      payload.dp = distributionPoints;
    }
    if (signingKey) {
      payload.pk = signingKey;
    }
    return JSON.stringify(payload);
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
      createForm: { name: '', method: 'password', password: '', confirmPassword: '', distributionPoints: '' },
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
        const { name, method, password, confirmPassword, distributionPoints } = this.createForm;

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

        // Parse distribution points (one per line or comma-separated)
        const distPoints = distributionPoints
          ? distributionPoints.split(/[\n,]/).map(s => s.trim()).filter(s => s)
          : null;
        console.log('[createIdentity] parsed distPoints:', distPoints);

        Alpine.store('app').loading = true;

        try {
          console.log('[createIdentity] calling KeyStore.createIdentityWithPassword...');
          const result = await KeyStore.createIdentityWithPassword(name, password, distPoints);
          console.log('[createIdentity] identity created locally, hash:', result.identity.identityHash);
          console.log('[createIdentity] identity.distributionPoints:', result.identity.distributionPoints);

          try {
            // Use stored genesis event to ensure hash matches
            console.log('[createIdentity] syncing genesis event to server');
            await api.submitGenesisEvent(result.identity.genesisEvent);
            console.log('[createIdentity] api.submitGenesisEvent succeeded');
          } catch (e) {
            console.warn('[createIdentity] Failed to register identity with API:', e);
          }

          SessionKeys.set(result.identity.identityHash, result.keyPair);
          Alpine.store('identity').setActive(result.identity.identityHash);

          this.showCreateModal = false;
          this.createForm = { name: '', method: 'password', password: '', confirmPassword: '', distributionPoints: '' };

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

          // Ensure identity exists on server before creating session
          try {
            await api.getIdentity(this.unlockingIdentity.identityHash);
          } catch (e) {
            if (e.status === 404) {
              // Identity not on server, sync it using stored genesis event
              const localIdentity = KeyStore.getIdentity(this.unlockingIdentity.identityHash);
              if (localIdentity?.genesisEvent) {
                await api.submitGenesisEvent(localIdentity.genesisEvent);
              } else {
                // Fallback: create new genesis (hash will differ!)
                await api.createIdentity(keyPair, localIdentity?.name || null, localIdentity?.distributionPoints || null);
              }
            }
          }

          // Now create session
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
      distributionPoints: [],
      loading: false,
      lastLoadedHash: null,
      showDistributionModal: false,
      editDistributionPoints: '',

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
          console.log('[load] API response:', data);
          console.log('[load] data.sigchain:', data.sigchain);
          this.sigchain = data.sigchain || [];
          this.devices = data.devices || [];
          this.recovery = data.recovery || null;
          // Consumer-side: extract distribution_points from events
          this.distributionPoints = SigchainUtils.getLatestField(this.sigchain, 'distribution_points', []);
          console.log('[load] loaded sigchain.length:', this.sigchain.length);
        } catch (e) {
          console.warn('[load] Failed to load identity from API:', e);
          // Identity not on server - try to register it if unlocked
          const keyPair = SessionKeys.get(activeHash);
          console.log('[load] keyPair available:', !!keyPair);
          if (keyPair) {
            console.log('[load] Identity not on server, attempting to register...');
            try {
              const localIdentity = KeyStore.getIdentity(activeHash);
              console.log('[load] localIdentity:', localIdentity?.name, 'hasGenesisEvent:', !!localIdentity?.genesisEvent);

              let createResult;
              if (localIdentity?.genesisEvent) {
                // Use stored genesis event to ensure hash matches
                createResult = await api.submitGenesisEvent(localIdentity.genesisEvent);
              } else {
                // Fallback: create new genesis (may have different hash)
                console.log('[load] No stored genesis, creating new one');
                createResult = await api.createIdentity(keyPair, localIdentity?.name || null, localIdentity?.distributionPoints || null);
              }
              console.log('[load] createIdentity result:', createResult);
              console.log('[load] server identity_hash:', createResult.identity_hash);
              const serverHash = createResult.identity_hash;
              if (serverHash !== activeHash) {
                console.warn('[load] Hash mismatch! local:', activeHash, 'server:', serverHash);
              }
              console.log('[load] Identity registered, reloading...');
              // Reload to get the sigchain
              const data = await api.getIdentity(serverHash);
              this.sigchain = data.sigchain || [];
              this.devices = data.devices || [];
              this.recovery = data.recovery || null;
              this.distributionPoints = SigchainUtils.getLatestField(this.sigchain, 'distribution_points', []);
              Alpine.store('app').showSuccess('Identity synced to server');
              return;
            } catch (syncErr) {
              console.error('[load] Failed to sync identity to server:', syncErr);
              Alpine.store('app').showError('Failed to sync identity: ' + syncErr.message);
            }
          } else {
            console.log('[load] Identity not unlocked, cannot sync');
          }
          this.sigchain = [];
          this.devices = [];
          this.recovery = null;
          this.distributionPoints = [];
        } finally {
          this.loading = false;
        }
      },

      openDistributionModal() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!SessionKeys.isUnlocked(activeHash)) {
          Alpine.store('app').showError('Identity must be unlocked first');
          return;
        }
        this.editDistributionPoints = this.distributionPoints.join('\n');
        this.showDistributionModal = true;
      },

      async saveDistributionPoints() {
        const activeHash = Alpine.store('identity').activeHash;
        console.log('[saveDistributionPoints] activeHash:', activeHash);
        console.log('[saveDistributionPoints] this.sigchain.length:', this.sigchain.length);
        console.log('[saveDistributionPoints] this.sigchain:', this.sigchain);

        const keyPair = SessionKeys.get(activeHash);
        if (!keyPair) {
          Alpine.store('app').showError('Identity must be unlocked');
          return;
        }

        const points = this.editDistributionPoints
          .split(/[\n,]/)
          .map(s => s.trim())
          .filter(s => s);

        // Get prev hash (last event in sigchain)
        const prevHash = this.sigchain.length > 0
          ? await this.getEventHash(this.sigchain[this.sigchain.length - 1])
          : null;
        console.log('[saveDistributionPoints] prevHash:', prevHash);

        if (!prevHash) {
          Alpine.store('app').showError('Cannot determine sigchain head');
          return;
        }

        Alpine.store('app').loading = true;

        try {
          const event = api.createSetDistributionEvent(keyPair, prevHash, points);
          await api.submitEvent(activeHash, event);

          this.distributionPoints = points;
          this.sigchain.push(event);
          this.showDistributionModal = false;
          Alpine.store('app').showSuccess('Distribution points updated');
        } catch (e) {
          Alpine.store('app').showError('Failed to update: ' + e.message);
        } finally {
          Alpine.store('app').loading = false;
        }
      },

      async getEventHash(event) {
        // Compute SHA-256 hash of canonical JSON
        const canonical = JSON.stringify(event, Object.keys(event).sort());
        return await Crypto.sha256Hex(canonical);
      },

      get activeDevices() { return this.devices; },
    }));

    // QR manager
    Alpine.data('qrManager', () => ({
      identityHash: null,
      scanning: false,

      async showIdentityQR(identityHash, distributionPoints = [], signingKey = null) {
        if (!identityHash) return;
        this.identityHash = identityHash;

        await this.$nextTick();
        const container = this.$refs.qrContainer;
        if (container && typeof QRCode !== 'undefined') {
          container.innerHTML = '';
          const canvas = document.createElement('canvas');
          container.appendChild(canvas);
          const qrData = createIdentityQR(identityHash, distributionPoints, signingKey);
          console.log('[showIdentityQR] QR data:', qrData);
          QRCode.toCanvas(canvas, qrData, {
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

    // Directory manager - shows all identities on server
    Alpine.data('directoryManager', () => ({
      identities: [],
      loading: false,

      init() {
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'directory') this.load();
        });
        if (Alpine.store('app').currentView === 'directory') {
          this.load();
        }
      },

      async load() {
        this.loading = true;
        try {
          const data = await api.listServerIdentities();
          this.identities = data.identities || [];
        } catch (e) {
          console.warn('Failed to load server identities:', e);
          this.identities = [];
        } finally {
          this.loading = false;
        }
      },
    }));

    // Messages manager
    Alpine.data('messagesManager', () => ({
      messages: [],
      messageText: '',
      loading: false,
      publishing: false,

      init() {
        this.$watch('$store.app.currentView', (view) => {
          if (view === 'messages') this.load();
        });
        if (Alpine.store('app').currentView === 'messages') {
          this.load();
        }
      },

      async load() {
        this.loading = true;
        try {
          const data = await api.listMessages();
          this.messages = data.messages || [];
        } catch (e) {
          console.warn('Failed to load messages:', e);
          this.messages = [];
        } finally {
          this.loading = false;
        }
      },

      async publish() {
        const activeHash = Alpine.store('identity').activeHash;
        if (!activeHash) {
          Alpine.store('app').showError('No identity selected');
          return;
        }

        const keyPair = SessionKeys.get(activeHash);
        if (!keyPair) {
          Alpine.store('app').showError('Identity must be unlocked');
          return;
        }

        if (!this.messageText.trim()) {
          Alpine.store('app').showError('Message cannot be empty');
          return;
        }

        this.publishing = true;
        try {
          const timestamp = Math.floor(Date.now() / 1000);
          const message = {
            type: 'public',
            sender: activeHash,
            content: {
              content_type: 'text/plain',
              body: this.messageText.trim(),
            },
            created_at: timestamp,
            reply_to: null,
            request_receipt: 'none',
            request_transit_report: false,
          };

          // Sign the message (use canonicalize for proper key sorting)
          const signable = canonicalize(message);
          console.log('[publish] signable:', signable);
          console.log('[publish] signing with pubkey:', keyPair.signing.publicKey);
          message.signature = Crypto.sign(signable, keyPair.signing.secretKey);
          console.log('[publish] signature:', message.signature);

          await api.publishMessage(message);
          Alpine.store('app').showSuccess('Message published');
          this.messageText = '';
          this.load(); // Refresh list
        } catch (e) {
          console.error('[publish] error:', e);
          Alpine.store('app').showError('Failed to publish: ' + e.message);
        } finally {
          this.publishing = false;
        }
      },
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
        a.download = `nodetide-backup-${Date.now()}.json`;
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
