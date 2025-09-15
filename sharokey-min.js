/**
 * Sharokey JavaScript Library - Simple Version
 * Single file for easy browser integration
 * API matches CLI commands exactly
 * 
 * Usage:
 *   <script src="sharokey.js"></script>
 *   <script>
 *     Sharokey.config({token: 'your-token'});
 *     Sharokey.create("My secret", 24, 1).then(secret => {
 *       console.log('URL:', secret.share_url);
 *     });
 *   </script>
 * 
 * @version 1.0.0
 */

(function(global) {
    'use strict';

    // Configuration globale
    let config = {
        token: null,
        apiUrl: 'https://api.sharokey.com/api/v1',
        timeout: 30000
    };

    // Constantes de chiffrement
    const CRYPTO_CONFIG = {
        CHARSET: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        PBKDF2_ITERATIONS: 10000,
        AES_KEY_LENGTH: 256,
        IV_LENGTH: 12,
        SALT_LENGTH: 16,
        KEY_A_LENGTH: 8,
        KEY_B_LENGTH: 24
    };

    /**
     * Vérifier si Web Crypto est disponible
     */
    function checkCryptoSupport() {
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('Web Crypto API not supported. Please use a modern browser.');
        }
    }

    /**
     * Générer une chaîne alphanummérique aléatoire
     */
    function generateAlphanumericKey(length) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        
        return Array.from(array, byte => 
            CRYPTO_CONFIG.CHARSET[byte % CRYPTO_CONFIG.CHARSET.length]
        ).join('');
    }

    /**
     * Générer des bytes aléatoires
     */
    function generateRandomBytes(length) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return array;
    }

    /**
     * Convertir ArrayBuffer en Base64
     */
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const chunkSize = 1024;
        
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.slice(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        
        return btoa(binary);
    }

    /**
     * Chiffrer un message avec AES-GCM
     */
    async function encryptMessage(content, keyString) {
        checkCryptoSupport();
        
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(content);
        
        // Générer salt et IV
        const salt = generateRandomBytes(CRYPTO_CONFIG.SALT_LENGTH);
        const iv = generateRandomBytes(CRYPTO_CONFIG.IV_LENGTH);
        
        // Importer la clé de base
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(keyString),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Dériver la clé AES
        const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: CRYPTO_CONFIG.AES_KEY_LENGTH },
            false,
            ['encrypt']
        );

        // Chiffrer
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            messageBytes
        );

        return {
            content: arrayBufferToBase64(encryptedBuffer),
            iv: arrayBufferToBase64(iv),
            salt: arrayBufferToBase64(salt),
            keyA: keyString.substring(0, CRYPTO_CONFIG.KEY_A_LENGTH),
            keyB: keyString.substring(CRYPTO_CONFIG.KEY_A_LENGTH)
        };
    }

    /**
     * Chiffrer un fichier avec les mêmes clés que le contenu principal
     * (Basé sur la référence REPRISE_CONVERSATION.md)
     */
    async function encryptFileAttachment(file, keyString, ivBase64, saltBase64) {
        checkCryptoSupport();
        
        const arrayBuffer = await file.arrayBuffer();
        const ivBytes = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
        const saltBytes = Uint8Array.from(atob(saltBase64), c => c.charCodeAt(0));
        const encoder = new TextEncoder();

        // Import key material (full key A+B)
        const keyMaterial = await window.crypto.subtle.importKey(
            'raw',
            encoder.encode(keyString),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive AES-GCM key from PBKDF2
        const key = await window.crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: CRYPTO_CONFIG.AES_KEY_LENGTH },
            false,
            ['encrypt']
        );

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes
            },
            key,
            arrayBuffer
        );

        // Convert to base64 by chunks (matches reference implementation)
        return arrayBufferToBase64(encryptedBuffer);
    }

    /**
     * Faire une requête HTTP
     */
    async function makeRequest(method, endpoint, data = null) {
        if (!config.token) {
            throw new Error('Token not configured. Use Sharokey.config({token: "your-token"}) first.');
        }

        const url = `${config.apiUrl}${endpoint}`;
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${config.token}`
            }
        };

        if (data && (method === 'POST' || method === 'PUT')) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(url, options);
            const responseData = await response.json();

            if (!response.ok) {
                throw new Error(responseData.message || `HTTP ${response.status}`);
            }

            return responseData;
        } catch (error) {
            throw new Error(`API Error: ${error.message}`);
        }
    }

    /**
     * Valider les paramètres de création
     */
    function validateCreateParams(content, hours, views) {
        if (!content || typeof content !== 'string' || content.trim().length === 0) {
            throw new Error('Content is required and must be a non-empty string');
        }

        hours = parseInt(hours);
        views = parseInt(views);
        
        if (!hours) {
            throw new Error('Hours parameter is required');
        }
        if (!views) {
            throw new Error('Views parameter is required');
        }

        return { content: content.trim(), hours, views };
    }

    /**
     * Valider les paramètres de sécurité étendus
     */
    function validateSecurityParams(ipWhitelist, geolocation) {
        // Validation IP whitelist (max 255 caractères)
        if (ipWhitelist && ipWhitelist.length > 255) {
            throw new Error('IP whitelist must be 255 characters or less');
        }

        // Validation geolocation (max 255 caractères)
        if (geolocation && geolocation.length > 255) {
            throw new Error('Geolocation must be 255 characters or less');
        }

        // Validation format IP whitelist (optionnelle)
        if (ipWhitelist) {
            const ips = ipWhitelist.split(',').map(ip => ip.trim());
            for (const ip of ips) {
                // Validation format de base
                const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
                if (!ipPattern.test(ip)) {
                    throw new Error(`Invalid IP format: ${ip}. Use format: 192.168.1.1`);
                }
                
                // Validation des octets (0-255)
                const octets = ip.split('.').map(Number);
                if (octets.some(octet => octet < 0 || octet > 255)) {
                    throw new Error(`Invalid IP range: ${ip}. Each octet must be 0-255`);
                }
            }
        }

        // Validation format geolocation (codes pays ISO)
        if (geolocation) {
            const countryPattern = /^[A-Z]{2}$/;
            const countries = geolocation.split(',').map(c => c.trim().toUpperCase());
            for (const country of countries) {
                if (!countryPattern.test(country)) {
                    throw new Error(`Invalid country code: ${country}. Use ISO 2-letter codes like FR,US,CA`);
                }
            }
        }
    }

    /**
     * Valider les attachments (max 10 fichiers, 10MB total)
     */
    function validateAttachments(attachments) {
        const MAX_FILES = 10;
        const MAX_TOTAL_SIZE = 10 * 1024 * 1024; // 10MB

        if (!Array.isArray(attachments)) {
            throw new Error('Attachments must be an array of File objects');
        }

        if (attachments.length > MAX_FILES) {
            throw new Error(`Too many attachments. Maximum ${MAX_FILES} files allowed, got ${attachments.length}`);
        }

        let totalSize = 0;
        for (const file of attachments) {
            if (!(file instanceof File)) {
                throw new Error('Each attachment must be a File object');
            }

            totalSize += file.size;
            if (totalSize > MAX_TOTAL_SIZE) {
                throw new Error(`Total attachments size too large: ${Math.round(totalSize / (1024 * 1024))}MB. Maximum 10MB allowed`);
            }
        }

        return true;
    }

    // API Publique Sharokey
    const Sharokey = {
        /**
         * Configurer Sharokey (comme "sharokey config")
         * @param {Object} options - Options de configuration
         * @param {string} options.token - Token d'authentification (requis)
         * @param {string} [options.apiUrl] - URL de l'API
         * @param {number} [options.timeout] - Timeout des requêtes
         */
        config: function(options) {
            if (!options || typeof options !== 'object') {
                throw new Error('Configuration object required');
            }

            if (!options.token) {
                throw new Error('Token is required in configuration');
            }

            Object.assign(config, options);
            return this;
        },

        /**
         * Créer un secret (comme "sharokey create")
         * @param {string} content - Contenu du secret
         * @param {number} [hours=24] - Heures avant expiration
         * @param {number} [views=1] - Nombre maximum de vues
         * @param {Object} [options] - Options supplémentaires
         * @param {string} [options.description] - Description du secret
         * @param {string} [options.message] - Message pour le destinataire
         * @param {string} [options.password] - Mot de passe de protection
         * @param {boolean} [options.captcha] - Activer la vérification CAPTCHA
         * @param {string} [options.ipWhitelist] - Liste d'IPs autorisées (séparées par virgules)
         * @param {string} [options.geolocation] - Codes pays autorisés (séparés par virgules)
         * @param {string} [options.otpEmail] - Email pour OTP
         * @param {string} [options.otpPhone] - Téléphone pour OTP
         * @param {File[]} [options.attachments] - Fichiers à attacher (max 10 fichiers, 10MB total)
         * @returns {Promise<Object>} Secret créé avec share_url
         */
        create: async function(content, hours, views, options = {}) {
            const params = validateCreateParams(content, hours, views);
            
            // Validation OTP (mutuellement exclusives)
            if (options.otpEmail && options.otpPhone) {
                throw new Error('Cannot use both otpEmail and otpPhone options simultaneously');
            }

            // Validation format email OTP
            if (options.otpEmail) {
                const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailPattern.test(options.otpEmail)) {
                    throw new Error('Invalid email format for OTP');
                }
            }

            // Validation format téléphone OTP
            if (options.otpPhone) {
                const phonePattern = /^\+\d{11,15}$/; // Format +33674747474
                if (!phonePattern.test(options.otpPhone)) {
                    throw new Error('Invalid phone format for OTP. Use format: +33674747474');
                }
            }

            // Valider les paramètres de sécurité étendus
            validateSecurityParams(options.ipWhitelist, options.geolocation);

            // Valider les attachments si fournis
            if (options.attachments && options.attachments.length > 0) {
                validateAttachments(options.attachments);
            }
            
            // Générer les clés
            const keyA = generateAlphanumericKey(CRYPTO_CONFIG.KEY_A_LENGTH);
            const keyB = generateAlphanumericKey(CRYPTO_CONFIG.KEY_B_LENGTH);
            const keyString = keyA + keyB;

            // Chiffrer le contenu
            const encrypted = await encryptMessage(params.content, keyString);

            // Préparer les données pour l'API
            const payload = {
                content: encrypted.content,
                iv: encrypted.iv,
                salt: encrypted.salt,
                key: encrypted.keyA,
                maximum_views: params.views,
                expiration_hours: params.hours,
                attachments: []
            };

            // Chiffrer les attachments si fournis
            if (options.attachments && options.attachments.length > 0) {
                for (const file of options.attachments) {
                    try {
                        const encryptedFileData = await encryptFileAttachment(
                            file, 
                            keyString, 
                            encrypted.iv, 
                            encrypted.salt
                        );
                        
                        payload.attachments.push({
                            name: file.name,
                            data: encryptedFileData
                        });
                    } catch (error) {
                        throw new Error(`Failed to encrypt file ${file.name}: ${error.message}`);
                    }
                }

                // Calculer la taille totale pour l'API
                const totalSize = options.attachments.reduce((sum, file) => sum + file.size, 0);
                payload.attachments_total_size = totalSize;
            }

            // Ajouter les options supplémentaires
            if (options.description) payload.description = options.description;
            if (options.message) payload.message = options.message;
            if (options.password) payload.password = options.password;
            if (options.captcha) payload.captcha = options.captcha;
            if (options.ipWhitelist) payload.ip_whitelist = options.ipWhitelist;
            if (options.geolocation) payload.geolocation = options.geolocation;
            if (options.otpEmail) {
                payload.otp_type = 'email';
                payload.otp_receiver = options.otpEmail;
            }
            if (options.otpPhone) {
                payload.otp_type = 'phone';
                payload.otp_receiver = options.otpPhone;
            }

            // Envoyer à l'API
            const response = await makeRequest('POST', '/secrets', payload);

            // Construire l'URL complète avec keyB
            const secret = response.data;
            if (secret.access_url) {
                secret.share_url = `${secret.access_url}#${keyB}`;
            }

            return secret;
        },

        /**
         * Lister les secrets (comme "sharokey list")
         * @param {Object} [options] - Options de filtrage
         * @param {number} [options.limit=50] - Limite de résultats
         * @param {string} [options.status] - Filtrer par statut (active|expired)
         * @param {string} [options.creator] - Filtrer par créateur
         * @param {string} [options.search] - Recherche textuelle
         * @returns {Promise<Object>} Liste des secrets
         */
        list: async function(options = {}) {
            const params = new URLSearchParams();
            
            if (options.limit) params.set('limit', options.limit);
            if (options.status) params.set('status', options.status);
            if (options.creator) params.set('creator', options.creator);
            if (options.search) params.set('search', options.search);

            const queryString = params.toString();
            const endpoint = queryString ? `/secrets?${queryString}` : '/secrets';
            
            return await makeRequest('GET', endpoint);
        },

        /**
         * Obtenir les détails d'un secret (comme "sharokey get")
         * @param {string} slug - Identifiant du secret
         * @returns {Promise<Object>} Détails du secret
         */
        get: async function(slug) {
            if (!slug || typeof slug !== 'string') {
                throw new Error('Secret slug is required');
            }

            return await makeRequest('GET', `/secrets/${slug.trim()}`);
        },

        /**
         * Supprimer un secret (comme "sharokey delete")
         * @param {string} slug - Identifiant du secret
         * @returns {Promise<Object>} Confirmation de suppression
         */
        delete: async function(slug) {
            if (!slug || typeof slug !== 'string') {
                throw new Error('Secret slug is required');
            }

            return await makeRequest('DELETE', `/secrets/${slug.trim()}`);
        },

        /**
         * Obtenir les statistiques (comme "sharokey stats")
         * @returns {Promise<Object>} Statistiques d'usage
         */
        stats: async function() {
            return await makeRequest('GET', '/secrets-stats');
        },



        /**
         * Tester la connectivité API (comme "sharokey test")
         * @returns {Promise<Object>} Résultats des tests de connectivité
         */
        test: async function() {
            const results = {
                config: false,
                network: false,
                auth: false,
                read: false,
                stats: false,
                total: 5,
                passed: 0,
                success: false
            };

            try {
                // 1. Test configuration
                if (config.token) {
                    results.config = true;
                    results.passed++;
                }

                // 2. Test réseau (health endpoint)
                try {
                    await makeRequest('GET', '/health');
                    results.network = true;
                    results.passed++;
                } catch (e) {
                    // Continue les autres tests même si health fail
                }

                // 3. Test authentification + lecture
                try {
                    await this.list({ limit: 1 });
                    results.auth = true;
                    results.read = true;
                    results.passed += 2;
                } catch (e) {
                    // Auth ou read a échoué
                }

                // 4. Test statistiques
                try {
                    await this.stats();
                    results.stats = true;
                    results.passed++;
                } catch (e) {
                    // Stats a échoué
                }

                results.success = results.passed === results.total;
                return results;

            } catch (error) {
                results.error = error.message;
                return results;
            }
        },

        /**
         * Tester la connectivité API (version simple, compatibilité)
         * @returns {Promise<boolean>} True si connecté
         */
        testConnection: async function() {
            const results = await this.test();
            return results.success;
        },

        /**
         * Obtenir la configuration actuelle
         * @returns {Object} Configuration actuelle (sans le token)
         */
        getConfig: function() {
            return {
                apiUrl: config.apiUrl,
                timeout: config.timeout,
                hasToken: !!config.token
            };
        },

        // ===== SECRET REQUEST METHODS =====

        /**
         * Créer une demande de secret
         * @param {Object} options - Options de la demande
         * @param {string} [options.message] - Message pour le destinataire
         * @param {string} [options.description] - Description pour usage interne
         * @param {number} options.secretExpirationHours - Heures avant expiration du secret (1-1000, REQUIS)
         * @param {number} options.requestExpirationHours - Heures avant expiration de la demande (1-1000, REQUIS)
         * @param {number} options.maximumViews - Nombre maximum de vues (1-10, REQUIS)
         * @param {string} [options.emailTo] - Email du destinataire
         * @param {string} [options.emailReply] - Email de réponse automatique
         * @param {string} [options.locale] - Langue pour l'email ('en' ou 'fr')
         * @returns {Promise<Object>} Demande de secret créée
         */
        createRequest: async function(options = {}) {
            // Validation des paramètres requis
            if (!options.secretExpirationHours) {
                throw new Error('secretExpirationHours is required (1-1000 hours)');
            }
            if (!options.requestExpirationHours) {
                throw new Error('requestExpirationHours is required (1-1000 hours)');
            }
            if (!options.maximumViews) {
                throw new Error('maximumViews is required (1-10 views)');
            }

            // Validation des limites
            const secretHours = parseInt(options.secretExpirationHours);
            const requestHours = parseInt(options.requestExpirationHours);
            const maxViews = parseInt(options.maximumViews);

            if (secretHours < 1 || secretHours > 1000) {
                throw new Error('secretExpirationHours must be between 1 and 1000');
            }
            if (requestHours < 1 || requestHours > 1000) {
                throw new Error('requestExpirationHours must be between 1 and 1000');
            }
            if (maxViews < 1 || maxViews > 10) {
                throw new Error('maximumViews must be between 1 and 10');
            }

            const requestData = {
                secret_expiration_hours: secretHours,
                request_expiration_hours: requestHours,
                maximum_views: maxViews
            };

            if (options.message) requestData.message = options.message;
            if (options.description) requestData.description = options.description;
            if (options.emailTo) requestData.email_to = options.emailTo;
            if (options.emailReply) requestData.email_reply = options.emailReply;
            if (options.locale) requestData.locale = options.locale;

            const response = await makeRequest('POST', '/requests', requestData);
            return response.data;
        },

        /**
         * Lister les demandes de secret
         * @param {Object} [options={}] - Options de filtrage
         * @param {number} [options.limit=50] - Nombre maximum de résultats
         * @param {string} [options.status] - Statut ('active' ou 'expired')
         * @param {string} [options.creator] - Email du créateur
         * @param {string} [options.search] - Recherche dans les descriptions
         * @returns {Promise<Object>} Liste des demandes de secret
         */
        listRequests: async function(options = {}) {
            const params = new URLSearchParams();
            
            if (options.limit) params.append('limit', options.limit);
            if (options.status) params.append('status', options.status);
            if (options.creator) params.append('creator', options.creator);
            if (options.search) params.append('search', options.search);

            const query = params.toString();
            const endpoint = query ? `/requests?${query}` : '/requests';
            
            const response = await makeRequest('GET', endpoint);
            return response;
        },

        /**
         * Obtenir les détails d'une demande de secret (comme "sharokey get-request")
         * @param {string} token - Token de la demande
         * @returns {Promise<Object>} Détails de la demande
         */
        getRequest: async function(token) {
            if (!token || typeof token !== 'string') {
                throw new Error('Token de demande requis');
            }
            
            const response = await makeRequest('GET', `/requests/${token.trim()}`);
            return response.data;
        },

        /**
         * Supprimer une demande de secret (comme "sharokey delete-request")
         * @param {string} token - Token de la demande
         * @returns {Promise<Object>} Réponse de suppression
         */
        deleteRequest: async function(token) {
            if (!token || typeof token !== 'string') {
                throw new Error('Token de demande requis');
            }
            
            return await makeRequest('DELETE', `/requests/${token.trim()}`);
        },

        /**
         * Obtenir les statistiques des demandes de secret
         * @returns {Promise<Object>} Statistiques des demandes
         */
        requestStats: async function() {
            return await makeRequest('GET', '/requests-stats');
        },

        /**
         * Version de la librairie
         */
        version: '1.0.0'
    };

    // Exposer dans le scope global
    if (typeof module !== 'undefined' && module.exports) {
        // Node.js
        module.exports = Sharokey;
    } else {
        // Browser
        global.Sharokey = Sharokey;
    }

})(typeof window !== 'undefined' ? window : global);
