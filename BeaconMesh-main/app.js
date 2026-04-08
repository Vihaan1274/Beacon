/**
 * BeaconMesh - Serverless P2P Chat Application
 * Version 2.0
 * 
 * A WebRTC-based peer-to-peer chat application using QR codes for signaling.
 * No backend server required - all connection data is exchanged via QR codes.
 */

const BeaconMesh = (function() {
    'use strict';

    // ==================== CONFIGURATION ====================
    const CONFIG = {
        // ICE servers for NAT traversal
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' },
            { urls: 'stun:stun2.l.google.com:19302' },
            { urls: 'stun:stun3.l.google.com:19302' },
            { urls: 'stun:stun4.l.google.com:19302' }
        ],
        
        // Timeouts (in milliseconds)
        iceGatheringTimeout: 10000,      // Max time to wait for ICE gathering
        forceGenerateDelay: 5000,        // Time before showing "Force Generate" button
        connectionTimeout: 30000,         // Max time to wait for connection
        
        // QR Code settings
        qrCodeSize: 280,
        qrCodeErrorCorrection: 'L',      // L = 7% recovery (smaller QR)
        
        // Message settings
        maxMessageLength: 1000,
        
        // Data channel settings
        dataChannelName: 'beaconmesh-v2',
        
        // Compression settings
        useCompression: true,
        maxCandidates: 4                 // Limit ICE candidates to keep QR small
    };

    // ==================== STATE ====================
    let state = {
        peerConnection: null,
        dataChannel: null,
        hostScanner: null,
        joinScanner: null,
        localSDP: '',
        isHost: false,
        connectionStartTime: null,
        pendingPermissionCallback: null,
        iceCandidates: [],
        iceGatheringComplete: false,
        forceGenerateTimeout: null,
        connectionCheckInterval: null
    };

    // ==================== UTILITY FUNCTIONS ====================
    
    /**
     * Compress SDP using aggressive optimization
     * Strips everything except essential fields and compresses with pako
     */
    function compressSDP(sdp) {
        const lines = sdp.split('\r\n');
        
        // Extract only essential data
        const essential = {
            v: 2,  // Protocol version
            u: '', // ice-ufrag
            p: '', // ice-pwd
            f: '', // fingerprint
            s: '', // setup
            c: []  // candidates (limited)
        };
        
        let candidateCount = 0;
        
        for (const line of lines) {
            if (line.startsWith('a=ice-ufrag:')) {
                essential.u = line.substring(12);
            } else if (line.startsWith('a=ice-pwd:')) {
                essential.p = line.substring(10);
            } else if (line.startsWith('a=fingerprint:')) {
                // Store fingerprint in shorter format
                const fp = line.substring(14);
                const [algo, hash] = fp.split(' ');
                // Only store hash, assume SHA-256
                essential.f = hash.replace(/:/g, '');
            } else if (line.startsWith('a=setup:')) {
                essential.s = line.substring(8)[0]; // Just first char: a/p/h
            } else if (line.startsWith('a=candidate:') && candidateCount < CONFIG.maxCandidates) {
                // Parse and compress candidate
                const compressed = compressCandidate(line);
                if (compressed) {
                    essential.c.push(compressed);
                    candidateCount++;
                }
            }
        }
        
        // JSON stringify and compress
        const json = JSON.stringify(essential);
        
        if (CONFIG.useCompression && typeof pako !== 'undefined') {
            try {
                const compressed = pako.deflate(json);
                const base64 = btoa(String.fromCharCode.apply(null, compressed));
                return 'Z' + base64; // 'Z' prefix indicates zlib compression
            } catch (e) {
                console.warn('Compression failed, using plain base64:', e);
            }
        }
        
        return 'B' + btoa(json); // 'B' prefix indicates plain base64
    }

    /**
     * Compress a single ICE candidate line
     */
    function compressCandidate(candidateLine) {
        // Format: a=candidate:foundation component transport priority ip port type ...
        const match = candidateLine.match(/a=candidate:(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+typ\s+(\S+)/);
        
        if (!match) return null;
        
        const [, foundation, component, transport, priority, ip, port, type] = match;
        
        // Only keep host and srflx candidates
        if (type !== 'host' && type !== 'srflx') return null;
        
        // Super compressed format
        return [
            foundation.substring(0, 8), // Truncate foundation
            ip,
            port,
            type[0] // h for host, s for srflx
        ].join('|');
    }

    /**
     * Decompress SDP back to full format
     */
    function decompressSDP(compressed, type) {
        try {
            let json;
            
            if (compressed.startsWith('Z')) {
                // Zlib compressed
                const base64 = compressed.substring(1);
                const binary = atob(base64);
                const bytes = new Uint8Array(binary.length);
                for (let i = 0; i < binary.length; i++) {
                    bytes[i] = binary.charCodeAt(i);
                }
                json = pako.inflate(bytes, { to: 'string' });
            } else if (compressed.startsWith('B')) {
                // Plain base64
                json = atob(compressed.substring(1));
            } else {
                // Legacy format or raw data
                json = atob(compressed);
            }
            
            const data = JSON.parse(json);
            
            // Reconstruct full SDP
            return reconstructFullSDP(data, type);
            
        } catch (e) {
            console.error('Decompression error:', e);
            throw new Error('Invalid QR code data');
        }
    }

    /**
     * Reconstruct full SDP from compressed data
     */
    function reconstructFullSDP(data, type) {
        // Restore fingerprint
        const fingerprintHex = data.f;
        const fingerprintFormatted = fingerprintHex.match(/.{2}/g).join(':').toUpperCase();
        
        // Restore setup value
        const setupMap = { 'a': 'actpass', 'p': 'passive', 'h': 'active' };
        const setup = setupMap[data.s] || 'actpass';
        
        // Build SDP
        let sdp = [
            'v=0',
            `o=- ${Date.now()} 2 IN IP4 127.0.0.1`,
            's=-',
            't=0 0',
            'a=group:BUNDLE 0',
            'a=extmap-allow-mixed',
            'a=msid-semantic: WMS',
            'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
            'c=IN IP4 0.0.0.0',
            'a=ice-options:trickle',
            `a=ice-ufrag:${data.u}`,
            `a=ice-pwd:${data.p}`,
            `a=fingerprint:sha-256 ${fingerprintFormatted}`,
            `a=setup:${type === 'offer' ? 'actpass' : 'active'}`,
            'a=mid:0',
            'a=sctp-port:5000',
            'a=max-message-size:262144'
        ];
        
        // Add candidates
        if (data.c && data.c.length > 0) {
            for (const candidate of data.c) {
                const [foundation, ip, port, typeChar] = candidate.split('|');
                const candidateType = typeChar === 'h' ? 'host' : 'srflx';
                const priority = candidateType === 'host' ? 2130706431 : 1694498815;
                
                sdp.push(`a=candidate:${foundation} 1 udp ${priority} ${ip} ${port} typ ${candidateType}`);
            }
        }
        
        return sdp.join('\r\n') + '\r\n';
    }

    /**
     * Generate QR Code
     */
    function generateQRCode(elementId, data) {
        const element = document.getElementById(elementId);
        element.innerHTML = '';
        
        try {
            new QRCode(element, {
                text: data,
                width: CONFIG.qrCodeSize,
                height: CONFIG.qrCodeSize,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel[CONFIG.qrCodeErrorCorrection]
            });
            return true;
        } catch (e) {
            console.error('QR generation failed:', e);
            showToast('error', 'QR Generation Failed', 'The data may be too large. Try regenerating.');
            return false;
        }
    }

    /**
     * Update progress indicators
     */
    function updateProgress(prefix, progress, status, subStatus) {
        const progressBar = document.getElementById(`${prefix}ProgressBar`);
        const statusEl = document.getElementById(`${prefix}LoadingStatus`);
        const subStatusEl = document.getElementById(`${prefix}SubStatus`);
        
        if (progressBar) progressBar.style.width = `${progress}%`;
        if (statusEl) statusEl.textContent = status;
        if (subStatusEl) subStatusEl.textContent = subStatus;
    }

    // ==================== SCREEN NAVIGATION ====================
    
    function showScreen(screenId) {
        const screens = ['homeScreen', 'hostScreen', 'joinScreen', 'chatScreen'];
        screens.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.toggle('hidden', id !== screenId);
            }
        });
    }

    function goHome() {
        cleanupConnection();
        stopScanners();
        resetUI();
        showScreen('homeScreen');
    }

    function resetUI() {
        // Reset host UI
        document.getElementById('hostQRLoading')?.classList.remove('hidden');
        document.getElementById('hostQRContainer')?.classList.add('hidden');
        document.getElementById('hostScanSection')?.classList.add('hidden');
        document.getElementById('hostForceGenerate')?.classList.add('hidden');
        document.getElementById('hostQRCode').innerHTML = '';
        
        // Reset join UI
        document.getElementById('joinScanSection')?.classList.remove('hidden');
        document.getElementById('joinQRSection')?.classList.add('hidden');
        document.getElementById('joinQRLoading')?.classList.remove('hidden');
        document.getElementById('joinQRContainer')?.classList.add('hidden');
        document.getElementById('joinForceGenerate')?.classList.add('hidden');
        document.getElementById('joinQRCode').innerHTML = '';
        
        // Reset steps
        resetSteps('host');
        resetSteps('join');
        
        // Clear inputs
        document.getElementById('hostAnswerInput').value = '';
        document.getElementById('joinOfferInput').value = '';
        
        // Reset progress bars
        updateProgress('host', 0, 'Initializing beacon...', 'Gathering network candidates');
        updateProgress('join', 0, 'Processing offer...', 'Creating answer');
    }

    function resetSteps(prefix) {
        for (let i = 1; i <= 3; i++) {
            const step = document.getElementById(`${prefix}Step${i}`);
            if (step) {
                step.classList.remove('active', 'completed');
                if (i === 1) step.classList.add('active');
            }
        }
    }

    function updateStep(prefix, stepNum, completed = false) {
        for (let i = 1; i <= 3; i++) {
            const step = document.getElementById(`${prefix}Step${i}`);
            if (step) {
                step.classList.remove('active', 'completed');
                if (i < stepNum || (i === stepNum && completed)) {
                    step.classList.add('completed');
                } else if (i === stepNum) {
                    step.classList.add('active');
                }
            }
        }
    }

    // ==================== TOAST NOTIFICATIONS ====================
    
    function showToast(type, title, message) {
        const container = document.getElementById('toastContainer');
        const id = 'toast-' + Date.now();
        
        const icons = {
            success: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>',
            error: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"/>',
            warning: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>',
            info: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>'
        };
        
        const colors = {
            success: 'border-neon bg-neon/10 text-neon',
            error: 'border-red-500 bg-red-900/50 text-red-400',
            warning: 'border-yellow-500 bg-yellow-900/50 text-yellow-400',
            info: 'border-cyber-blue bg-cyber-blue/10 text-cyber-blue'
        };
        
        const html = `
            <div id="${id}" class="toast ${colors[type]} transform translate-x-full opacity-0 transition-all duration-300">
                <svg class="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    ${icons[type]}
                </svg>
                <div class="flex-1 min-w-0">
                    <p class="font-bold text-sm">${title}</p>
                    <p class="text-xs opacity-80 truncate">${message}</p>
                </div>
                <button onclick="BeaconMesh.dismissToast('${id}')" class="opacity-60 hover:opacity-100">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        `;
        
        container.insertAdjacentHTML('beforeend', html);
        
        // Animate in
        requestAnimationFrame(() => {
            const toast = document.getElementById(id);
            toast.classList.remove('translate-x-full', 'opacity-0');
        });
        
        // Auto dismiss
        setTimeout(() => dismissToast(id), 5000);
    }

    function dismissToast(id) {
        const toast = document.getElementById(id);
        if (toast) {
            toast.classList.add('translate-x-full', 'opacity-0');
            setTimeout(() => toast.remove(), 300);
        }
    }

    // ==================== CAMERA & SCANNER ====================
    
    async function checkSecureContext() {
        if (!window.isSecureContext) {
            document.getElementById('httpsWarning')?.classList.remove('hidden');
            return false;
        }
        return true;
    }

    async function checkCameraPermission() {
        try {
            const result = await navigator.permissions.query({ name: 'camera' });
            return result.state === 'granted';
        } catch (e) {
            return false;
        }
    }

    function showPermissionModal(callback) {
        state.pendingPermissionCallback = callback;
        document.getElementById('permissionModal')?.classList.remove('hidden');
    }

    function hidePermissionModal() {
        document.getElementById('permissionModal')?.classList.add('hidden');
        state.pendingPermissionCallback = null;
    }

    async function requestCameraPermission() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true });
            stream.getTracks().forEach(track => track.stop());
            hidePermissionModal();
            if (state.pendingPermissionCallback) {
                state.pendingPermissionCallback();
            }
        } catch (e) {
            hidePermissionModal();
            showToast('error', 'Camera Denied', 'Please enable camera in browser settings');
        }
    }

    async function startScanner(elementId, onSuccess) {
        if (!await checkSecureContext()) {
            showToast('error', 'HTTPS Required', 'Camera requires a secure connection');
            return null;
        }

        const hasPermission = await checkCameraPermission();
        
        if (!hasPermission) {
            showPermissionModal(() => initScanner(elementId, onSuccess));
            return null;
        }
        
        return initScanner(elementId, onSuccess);
    }

    async function initScanner(elementId, onSuccess) {
        try {
            const scanner = new Html5Qrcode(elementId);
            
            await scanner.start(
                { facingMode: 'environment' },
                {
                    fps: 10,
                    qrbox: { width: 250, height: 250 },
                    aspectRatio: 1.0
                },
                (decodedText) => {
                    onSuccess(decodedText);
                },
                () => {} // Ignore scan errors
            );
            
            return scanner;
        } catch (e) {
            console.error('Scanner init error:', e);
            showToast('error', 'Camera Error', 'Failed to initialize camera');
            return null;
        }
    }

    function stopScanners() {
        if (state.hostScanner) {
            state.hostScanner.stop().catch(() => {});
            state.hostScanner = null;
        }
        if (state.joinScanner) {
            state.joinScanner.stop().catch(() => {});
            state.joinScanner = null;
        }
    }

    // ==================== WEBRTC CONNECTION ====================
    
    function createPeerConnection() {
        const pc = new RTCPeerConnection({ iceServers: CONFIG.iceServers });
        
        state.iceCandidates = [];
        state.iceGatheringComplete = false;
        
        pc.onicecandidate = (event) => {
            if (event.candidate) {
                state.iceCandidates.push(event.candidate);
                console.log('ICE candidate:', event.candidate.type, event.candidate.address);
            }
        };
        
        pc.onicegatheringstatechange = () => {
            console.log('ICE gathering state:', pc.iceGatheringState);
            if (pc.iceGatheringState === 'complete') {
                state.iceGatheringComplete = true;
            }
        };
        
        pc.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', pc.iceConnectionState);
        };
        
        pc.onconnectionstatechange = () => {
            console.log('Connection state:', pc.connectionState);
            
            if (pc.connectionState === 'connected') {
                onConnectionEstablished();
            } else if (pc.connectionState === 'failed') {
                showToast('error', 'Connection Failed', 'Unable to establish P2P connection');
                goHome();
            } else if (pc.connectionState === 'disconnected') {
                showToast('warning', 'Disconnected', 'Connection lost');
            }
        };
        
        return pc;
    }

    function setupDataChannel(channel) {
        channel.onopen = () => {
            console.log('Data channel opened');
            showToast('success', 'Connected!', 'Secure channel established');
        };
        
        channel.onclose = () => {
            console.log('Data channel closed');
        };
        
        channel.onerror = (error) => {
            console.error('Data channel error:', error);
        };
        
        channel.onmessage = (event) => {
            handleIncomingMessage(event.data);
        };
    }

    async function waitForICEGathering(pc, prefix) {
        return new Promise((resolve) => {
            let progress = 10;
            const startTime = Date.now();
            
            // Show force generate button after delay
            state.forceGenerateTimeout = setTimeout(() => {
                document.getElementById(`${prefix}ForceGenerate`)?.classList.remove('hidden');
            }, CONFIG.forceGenerateDelay);
            
            const checkComplete = () => {
                const elapsed = Date.now() - startTime;
                progress = Math.min(90, 10 + (elapsed / CONFIG.iceGatheringTimeout) * 80);
                
                updateProgress(prefix, progress, 
                    `Gathering candidates (${state.iceCandidates.length})...`,
                    `${Math.ceil((CONFIG.iceGatheringTimeout - elapsed) / 1000)}s remaining`
                );
                
                if (pc.iceGatheringState === 'complete' || elapsed >= CONFIG.iceGatheringTimeout) {
                    clearTimeout(state.forceGenerateTimeout);
                    updateProgress(prefix, 100, 'Complete!', 'Generating QR code');
                    resolve();
                } else if (state.iceCandidates.length >= CONFIG.maxCandidates) {
                    // We have enough candidates
                    clearTimeout(state.forceGenerateTimeout);
                    updateProgress(prefix, 100, 'Complete!', 'Generating QR code');
                    resolve();
                } else {
                    setTimeout(checkComplete, 200);
                }
            };
            
            checkComplete();
        });
    }

    // ==================== HOST FLOW ====================
    
    async function startHost() {
        state.isHost = true;
        showScreen('hostScreen');
        
        try {
            updateProgress('host', 5, 'Creating connection...', 'Initializing WebRTC');
            
            state.peerConnection = createPeerConnection();
            
            // Create data channel
            state.dataChannel = state.peerConnection.createDataChannel(CONFIG.dataChannelName, {
                ordered: true
            });
            setupDataChannel(state.dataChannel);
            
            updateProgress('host', 10, 'Creating offer...', 'Generating SDP');
            
            // Create offer
            const offer = await state.peerConnection.createOffer();
            await state.peerConnection.setLocalDescription(offer);
            
            // Wait for ICE gathering
            await waitForICEGathering(state.peerConnection, 'host');
            
            // Generate QR
            generateHostQR();
            
        } catch (e) {
            console.error('Host setup error:', e);
            showToast('error', 'Setup Failed', e.message);
            goHome();
        }
    }

    function generateHostQR() {
        const sdp = state.peerConnection.localDescription.sdp;
        state.localSDP = compressSDP(sdp);
        
        // Update stats
        document.getElementById('hostQRSize').textContent = state.localSDP.length;
        document.getElementById('hostCandidateCount').textContent = state.iceCandidates.length;
        
        // Check if QR will be scannable
        if (state.localSDP.length > 2000) {
            showToast('warning', 'Large QR Code', 'QR may be difficult to scan. Ensure good lighting.');
        }
        
        // Show QR
        document.getElementById('hostQRLoading').classList.add('hidden');
        document.getElementById('hostQRContainer').classList.remove('hidden');
        document.getElementById('hostForceGenerate').classList.add('hidden');
        
        if (!generateQRCode('hostQRCode', state.localSDP)) {
            showToast('error', 'QR Failed', 'Unable to generate QR code');
            return;
        }
        
        // Show scanner section
        document.getElementById('hostScanSection').classList.remove('hidden');
        
        // Start scanner for answer
        startScanner('hostScanner', async (data) => {
            if (state.hostScanner) {
                await state.hostScanner.stop();
                state.hostScanner = null;
            }
            await processHostAnswerData(data);
        }).then(scanner => {
            state.hostScanner = scanner;
        });
        
        updateStep('host', 2);
    }

    function forceGenerateHostQR() {
        clearTimeout(state.forceGenerateTimeout);
        generateHostQR();
    }

    async function processHostAnswerData(data) {
        try {
            showToast('info', 'Processing...', 'Validating answer data');
            
            const sdp = decompressSDP(data, 'answer');
            
            const answer = {
                type: 'answer',
                sdp: sdp
            };
            
            await state.peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
            
            updateStep('host', 3);
            showToast('success', 'Answer Received', 'Establishing connection...');
            
        } catch (e) {
            console.error('Error processing answer:', e);
            showToast('error', 'Invalid Answer', 'Please try scanning again');
            
            // Restart scanner
            state.hostScanner = await startScanner('hostScanner', processHostAnswerData);
        }
    }

    async function processHostAnswer() {
        const input = document.getElementById('hostAnswerInput').value.trim();
        if (input) {
            await processHostAnswerData(input);
        }
    }

    function copyHostSDP() {
        navigator.clipboard.writeText(state.localSDP).then(() => {
            showToast('success', 'Copied!', 'SDP copied to clipboard');
        });
    }

    function regenerateHostOffer() {
        // Reset and regenerate
        document.getElementById('hostQRLoading').classList.remove('hidden');
        document.getElementById('hostQRContainer').classList.add('hidden');
        
        state.iceCandidates = [];
        
        // Trigger ICE restart
        state.peerConnection.restartIce();
        
        setTimeout(() => {
            generateHostQR();
        }, 1000);
    }

    // ==================== JOIN FLOW ====================
    
    async function startJoin() {
        state.isHost = false;
        showScreen('joinScreen');
        
        // Start scanner
        state.joinScanner = await startScanner('joinScanner', async (data) => {
            if (state.joinScanner) {
                await state.joinScanner.stop();
                state.joinScanner = null;
            }
            await processJoinOfferData(data);
        });
    }

    async function processJoinOfferData(data) {
        try {
            showToast('info', 'Processing...', 'Validating offer data');
            
            // Switch to answer section
            document.getElementById('joinScanSection').classList.add('hidden');
            document.getElementById('joinQRSection').classList.remove('hidden');
            
            updateStep('join', 2);
            updateProgress('join', 10, 'Decoding offer...', 'Validating data');
            
            const sdp = decompressSDP(data, 'offer');
            
            updateProgress('join', 30, 'Creating connection...', 'Initializing WebRTC');
            
            // Create peer connection
            state.peerConnection = createPeerConnection();
            
            // Handle incoming data channel
            state.peerConnection.ondatachannel = (event) => {
                state.dataChannel = event.channel;
                setupDataChannel(state.dataChannel);
            };
            
            updateProgress('join', 50, 'Setting remote description...', 'Processing offer');
            
            // Set remote description
            const offer = {
                type: 'offer',
                sdp: sdp
            };
            
            await state.peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
            
            updateProgress('join', 60, 'Creating answer...', 'Generating response');
            
            // Create answer
            const answer = await state.peerConnection.createAnswer();
            await state.peerConnection.setLocalDescription(answer);
            
            // Wait for ICE gathering
            await waitForICEGathering(state.peerConnection, 'join');
            
            // Generate QR
            generateJoinQR();
            
        } catch (e) {
            console.error('Error processing offer:', e);
            showToast('error', 'Invalid Offer', 'Please try scanning again');
            
            // Go back to scanner
            document.getElementById('joinQRSection').classList.add('hidden');
            document.getElementById('joinScanSection').classList.remove('hidden');
            
            state.joinScanner = await startScanner('joinScanner', processJoinOfferData);
        }
    }

    function generateJoinQR() {
        const sdp = state.peerConnection.localDescription.sdp;
        state.localSDP = compressSDP(sdp);
        
        // Update stats
        document.getElementById('joinQRSize').textContent = state.localSDP.length;
        document.getElementById('joinCandidateCount').textContent = state.iceCandidates.length;
        
        // Show QR
        document.getElementById('joinQRLoading').classList.add('hidden');
        document.getElementById('joinQRContainer').classList.remove('hidden');
        document.getElementById('joinForceGenerate').classList.add('hidden');
        
        if (!generateQRCode('joinQRCode', state.localSDP)) {
            showToast('error', 'QR Failed', 'Unable to generate QR code');
            return;
        }
        
        showToast('success', 'Answer Ready', 'Show this QR code to the host');
    }

    function forceGenerateJoinQR() {
        clearTimeout(state.forceGenerateTimeout);
        generateJoinQR();
    }

    async function processJoinOffer() {
        const input = document.getElementById('joinOfferInput').value.trim();
        if (input) {
            await processJoinOfferData(input);
        }
    }

    function copyJoinSDP() {
        navigator.clipboard.writeText(state.localSDP).then(() => {
            showToast('success', 'Copied!', 'SDP copied to clipboard');
        });
    }

    // ==================== CHAT FUNCTIONALITY ====================
    
    function onConnectionEstablished() {
        state.connectionStartTime = Date.now();
        stopScanners();
        showScreen('chatScreen');
        
        // Update home stats
        document.getElementById('homeConnectionCount').textContent = '1';
        document.getElementById('homeStatusIndicator').textContent = '●';
        document.getElementById('homeStatusIndicator').classList.remove('text-yellow-500');
        document.getElementById('homeStatusIndicator').classList.add('text-neon');
        
        // Start connection duration timer
        updateConnectionDuration();
        state.connectionCheckInterval = setInterval(updateConnectionDuration, 1000);
        
        // Focus message input
        setTimeout(() => {
            document.getElementById('messageInput')?.focus();
        }, 100);
    }

    function updateConnectionDuration() {
        if (!state.connectionStartTime) return;
        
        const duration = Math.floor((Date.now() - state.connectionStartTime) / 1000);
        const minutes = Math.floor(duration / 60);
        const seconds = duration % 60;
        
        document.getElementById('connectionDuration').textContent = 
            `Connected ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }

    function sendMessage() {
        const input = document.getElementById('messageInput');
        const message = input.value.trim();
        
        if (!message) return;
        if (message.length > CONFIG.maxMessageLength) {
            showToast('warning', 'Message Too Long', `Max ${CONFIG.maxMessageLength} characters`);
            return;
        }
        
        if (state.dataChannel && state.dataChannel.readyState === 'open') {
            const payload = JSON.stringify({
                t: 'm', // type: message
                d: message, // data
                ts: Date.now()
                });
            
            state.dataChannel.send(payload);
            addMessageToChat(message, true);
            input.value = '';
            updateCharCount();
        } else {
            showToast('error', 'Not Connected', 'Connection not ready. Please wait...');
        }
    }

    function handleIncomingMessage(data) {
        try {
            const payload = JSON.parse(data);
            
            switch (payload.t) {
                case 'm': // message
                    addMessageToChat(payload.d, false);
                    // Play notification sound or vibrate
                    if (document.hidden && navigator.vibrate) {
                        navigator.vibrate(100);
                    }
                    break;
                case 'typing':
                    showTypingIndicator(payload.d);
                    break;
                case 'ping':
                    // Respond to ping
                    state.dataChannel.send(JSON.stringify({ t: 'pong', ts: Date.now() }));
                    break;
                default:
                    console.log('Unknown message type:', payload.t);
            }
        } catch (e) {
            console.error('Error parsing message:', e);
        }
    }

    function addMessageToChat(text, isSent) {
        const container = document.getElementById('chatMessages');
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const messageId = 'msg-' + Date.now();
        
        const messageHtml = `
            <div id="${messageId}" class="message-row ${isSent ? 'message-row-sent' : 'message-row-received'}">
                <div class="message ${isSent ? 'message-sent' : 'message-received'}">
                    <div class="message-content">${escapeHtml(text)}</div>
                    <div class="message-meta">
                        <span class="message-time">${time}</span>
                        ${isSent ? '<span class="message-status">✓</span>' : ''}
                    </div>
                </div>
            </div>
        `;
        
        container.insertAdjacentHTML('beforeend', messageHtml);
        
        // Smooth scroll to bottom
        requestAnimationFrame(() => {
            container.scrollTo({
                top: container.scrollHeight,
                behavior: 'smooth'
            });
        });
        
        // Animate message entry
        requestAnimationFrame(() => {
            const msg = document.getElementById(messageId);
            msg?.classList.add('message-animate-in');
        });
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        // Convert URLs to links
        let html = div.innerHTML;
        html = html.replace(
            /(https?:\/\/[^\s]+)/g, 
            '<a href="$1" target="_blank" rel="noopener noreferrer" class="text-cyber-blue underline">$1</a>'
        );
        return html;
    }

    function updateCharCount() {
        const input = document.getElementById('messageInput');
        const counter = document.getElementById('charCount');
        const length = input.value.length;
        
        counter.textContent = `${length}/${CONFIG.maxMessageLength}`;
        
        if (length > CONFIG.maxMessageLength * 0.9) {
            counter.classList.add('text-yellow-500');
        } else {
            counter.classList.remove('text-yellow-500');
        }
        
        if (length >= CONFIG.maxMessageLength) {
            counter.classList.add('text-red-500');
            counter.classList.remove('text-yellow-500');
        } else {
            counter.classList.remove('text-red-500');
        }
    }

    function showTypingIndicator(isTyping) {
        let indicator = document.getElementById('typingIndicator');
        
        if (isTyping && !indicator) {
            const container = document.getElementById('chatMessages');
            const html = `
                <div id="typingIndicator" class="message-row message-row-received">
                    <div class="message message-received typing-indicator">
                        <span class="typing-dot"></span>
                        <span class="typing-dot"></span>
                        <span class="typing-dot"></span>
                    </div>
                </div>
            `;
            container.insertAdjacentHTML('beforeend', html);
        } else if (!isTyping && indicator) {
            indicator.remove();
        }
    }

    // ==================== CONNECTION INFO ====================
    
    function showConnectionInfo() {
        const modal = document.getElementById('connectionInfoModal');
        const content = document.getElementById('connectionInfoContent');
        
        if (!state.peerConnection) {
            content.innerHTML = '<p class="text-gray-500">No active connection</p>';
            modal.classList.remove('hidden');
            return;
        }
        
        // Get connection stats
        const pc = state.peerConnection;
        const dc = state.dataChannel;
        
        const info = {
            'Connection State': pc.connectionState || 'Unknown',
            'ICE State': pc.iceConnectionState || 'Unknown',
            'Signaling State': pc.signalingState || 'Unknown',
            'Data Channel': dc ? dc.readyState : 'Not created',
            'Role': state.isHost ? 'Host (Initiator)' : 'Joiner (Responder)',
            'Connected For': formatDuration(Date.now() - state.connectionStartTime),
            'Local Candidates': state.iceCandidates.length,
            'Protocol': 'WebRTC DataChannel'
        };
        
        let html = '<div class="space-y-2">';
        for (const [key, value] of Object.entries(info)) {
            const valueClass = getValueClass(key, value);
            html += `
                <div class="flex justify-between items-center py-2 border-b border-gray-800">
                    <span class="text-gray-500 text-sm">${key}</span>
                    <span class="text-sm ${valueClass}">${value}</span>
                </div>
            `;
        }
        html += '</div>';
        
        // Add stats button
        html += `
            <button onclick="BeaconMesh.getDetailedStats()" class="mt-4 btn-secondary w-full">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>
                </svg>
                Get Detailed Stats
            </button>
        `;
        
        content.innerHTML = html;
        modal.classList.remove('hidden');
    }

    function getValueClass(key, value) {
        const successStates = ['connected', 'open', 'stable', 'complete'];
        const warningStates = ['connecting', 'checking', 'new'];
        const errorStates = ['failed', 'disconnected', 'closed'];
        
        const lowerValue = String(value).toLowerCase();
        
        if (successStates.some(s => lowerValue.includes(s))) {
            return 'text-neon';
        } else if (warningStates.some(s => lowerValue.includes(s))) {
            return 'text-yellow-500';
        } else if (errorStates.some(s => lowerValue.includes(s))) {
            return 'text-red-500';
        }
        return 'text-gray-300';
    }

    function formatDuration(ms) {
        if (!ms || ms < 0) return '0:00';
        
        const seconds = Math.floor(ms / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        
        if (hours > 0) {
            return `${hours}:${(minutes % 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`;
        }
        return `${minutes}:${(seconds % 60).toString().padStart(2, '0')}`;
    }

    function hideConnectionInfo() {
        document.getElementById('connectionInfoModal')?.classList.add('hidden');
    }

    async function getDetailedStats() {
        if (!state.peerConnection) {
            showToast('error', 'No Connection', 'No active connection to get stats from');
            return;
        }
        
        try {
            const stats = await state.peerConnection.getStats();
            let statsText = 'WebRTC Connection Stats\n';
            statsText += '========================\n\n';
            
            stats.forEach((report) => {
                if (report.type === 'candidate-pair' && report.state === 'succeeded') {
                    statsText += `Active Candidate Pair:\n`;
                    statsText += `  Local: ${report.localCandidateId}\n`;
                    statsText += `  Remote: ${report.remoteCandidateId}\n`;
                    statsText += `  Bytes Sent: ${report.bytesSent || 0}\n`;
                    statsText += `  Bytes Received: ${report.bytesReceived || 0}\n`;
                    statsText += `  Round Trip Time: ${report.currentRoundTripTime || 'N/A'}s\n\n`;
                }
                
                if (report.type === 'local-candidate' || report.type === 'remote-candidate') {
                    statsText += `${report.type}:\n`;
                    statsText += `  Address: ${report.address}:${report.port}\n`;
                    statsText += `  Protocol: ${report.protocol}\n`;
                    statsText += `  Type: ${report.candidateType}\n\n`;
                }
            });
            
            console.log(statsText);
            showToast('success', 'Stats Logged', 'Check browser console for detailed stats');
            
        } catch (e) {
            console.error('Failed to get stats:', e);
            showToast('error', 'Stats Error', 'Failed to retrieve connection stats');
        }
    }

    // ==================== DISCONNECT & CLEANUP ====================
    
    function disconnect() {
        if (confirm('Are you sure you want to disconnect?')) {
            // Send disconnect message if possible
            if (state.dataChannel && state.dataChannel.readyState === 'open') {
                try {
                    state.dataChannel.send(JSON.stringify({ t: 'disconnect' }));
                } catch (e) {
                    // Ignore errors during disconnect
                }
            }
            
            cleanupConnection();
            stopScanners();
            resetUI();
            clearChatMessages();
            showScreen('homeScreen');
            showToast('info', 'Disconnected', 'You have left the mesh');
        }
    }

    function cleanupConnection() {
        // Clear timers
        if (state.forceGenerateTimeout) {
            clearTimeout(state.forceGenerateTimeout);
            state.forceGenerateTimeout = null;
        }
        
        if (state.connectionCheckInterval) {
            clearInterval(state.connectionCheckInterval);
            state.connectionCheckInterval = null;
        }
        
        // Close data channel
        if (state.dataChannel) {
            try {
                state.dataChannel.close();
            } catch (e) {}
            state.dataChannel = null;
        }
        
        // Close peer connection
        if (state.peerConnection) {
            try {
                state.peerConnection.close();
            } catch (e) {}
            state.peerConnection = null;
        }
        
        // Reset state
        state.localSDP = '';
        state.iceCandidates = [];
        state.iceGatheringComplete = false;
        state.connectionStartTime = null;
        
        // Update UI stats
        document.getElementById('homeConnectionCount').textContent = '0';
        document.getElementById('homeStatusIndicator').textContent = '●';
        document.getElementById('homeStatusIndicator').classList.add('text-yellow-500');
        document.getElementById('homeStatusIndicator').classList.remove('text-neon');
    }

    function clearChatMessages() {
        const container = document.getElementById('chatMessages');
        container.innerHTML = `
            <div class="flex justify-center">
                <div class="system-message">
                    <svg class="w-4 h-4 text-neon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                    <div>
                        <p class="font-medium text-gray-300">End-to-end encrypted connection established</p>
                        <p class="text-gray-600 text-xs mt-1">Messages are transmitted directly between peers. No server involved.</p>
                    </div>
                </div>
            </div>
        `;
    }

    // ==================== INITIALIZATION ====================
    
    function init() {
        console.log('%c🔗 BeaconMesh v2.0 Initialized', 'color: #00ff41; font-size: 16px; font-weight: bold;');
        console.log('%cServerless P2P Communication', 'color: #666; font-size: 12px;');
        
        // Check for WebRTC support
        if (!window.RTCPeerConnection) {
            showToast('error', 'WebRTC Not Supported', 'Please use a modern browser');
            return;
        }
        
        // Check for secure context
        checkSecureContext();
        
        // Setup message input listener for char count
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.addEventListener('input', updateCharCount);
            
            // Typing indicator (optional - can be enabled)
            let typingTimeout;
            messageInput.addEventListener('input', () => {
                if (state.dataChannel && state.dataChannel.readyState === 'open') {
                    // Send typing indicator
                    // state.dataChannel.send(JSON.stringify({ t: 'typing', d: true }));
                    
                    clearTimeout(typingTimeout);
                    typingTimeout = setTimeout(() => {
                        // state.dataChannel.send(JSON.stringify({ t: 'typing', d: false }));
                    }, 1000);
                }
            });
        }
        
        // Handle page visibility
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                // Page is hidden
                console.log('Page hidden');
            } else {
                // Page is visible
                console.log('Page visible');
            }
        });
        
        // Handle beforeunload
        window.addEventListener('beforeunload', (e) => {
            if (state.peerConnection && state.peerConnection.connectionState === 'connected') {
                e.preventDefault();
                e.returnValue = 'You have an active connection. Are you sure you want to leave?';
            }
        });
        
        // Handle online/offline
        window.addEventListener('online', () => {
            showToast('success', 'Back Online', 'Network connection restored');
        });
        
        window.addEventListener('offline', () => {
            showToast('warning', 'Offline', 'Network connection lost');
        });
    }

    // ==================== HELPER FUNCTIONS ====================
    
    function toggleHowItWorks() {
        const panel = document.getElementById('howItWorksPanel');
        panel?.classList.toggle('hidden');
    }

    function dismissHttpsWarning() {
        document.getElementById('httpsWarning')?.classList.add('hidden');
    }

    // ==================== PUBLIC API ====================
    
    // Initialize on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose public methods
    return {
        // Navigation
        goHome,
        
        // Host flow
        startHost,
        processHostAnswer,
        copyHostSDP,
        regenerateHostOffer,
        forceGenerateHostQR,
        
        // Join flow
        startJoin,
        processJoinOffer,
        copyJoinSDP,
        forceGenerateJoinQR,
        
        // Chat
        sendMessage,
        
        // Connection
        disconnect,
        showConnectionInfo,
        hideConnectionInfo,
        getDetailedStats,
        
        // Modals
        showPermissionModal,
        hidePermissionModal,
        requestCameraPermission,
        
        // Toasts
        dismissToast,
        
        // Utils (for debugging)
        getState: () => ({ ...state }),
        getConfig: () => ({ ...CONFIG })
    };

})();

// Global helper functions
function toggleHowItWorks() {
    document.getElementById('howItWorksPanel')?.classList.toggle('hidden');
}

function dismissHttpsWarning() {
    document.getElementById('httpsWarning')?.classList.add('hidden');
}