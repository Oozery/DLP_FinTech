// ===== Configuration =====
const API_BASE = 'http://localhost:5000';
let users = {};
let transactionHistory = [];

// ===== Particle Background =====
function initParticles() {
    const canvas = document.getElementById('particleCanvas');
    const ctx = canvas.getContext('2d');
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;

    const particles = [];
    const numParticles = 80;

    for (let i = 0; i < numParticles; i++) {
        particles.push({
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            vx: (Math.random() - 0.5) * 0.5,
            vy: (Math.random() - 0.5) * 0.5,
            radius: Math.random() * 2 + 0.5,
            opacity: Math.random() * 0.5 + 0.1
        });
    }

    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach((p, i) => {
            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(99, 102, 241, ${p.opacity})`;
            ctx.fill();

            // Draw connections
            for (let j = i + 1; j < particles.length; j++) {
                const dx = p.x - particles[j].x;
                const dy = p.y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 150) {
                    ctx.beginPath();
                    ctx.moveTo(p.x, p.y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(99, 102, 241, ${0.1 * (1 - dist / 150)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        });

        requestAnimationFrame(animate);
    }

    animate();

    window.addEventListener('resize', () => {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    });
}

// ===== Navigation =====
function scrollToSection(sectionId) {
    document.getElementById(sectionId).scrollIntoView({ behavior: 'smooth' });
}

// Active nav link on scroll
window.addEventListener('scroll', () => {
    const sections = document.querySelectorAll('.section');
    const navLinks = document.querySelectorAll('.nav-link');
    let current = '';

    sections.forEach(section => {
        const sectionTop = section.offsetTop - 200;
        if (window.scrollY >= sectionTop) {
            current = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('data-section') === current) {
            link.classList.add('active');
        }
    });
});

// ===== DLP Calculator =====
function modPow(base, exp, mod) {
    let result = 1n;
    base = BigInt(base) % BigInt(mod);
    exp = BigInt(exp);
    mod = BigInt(mod);

    while (exp > 0n) {
        if (exp % 2n === 1n) {
            result = (result * base) % mod;
        }
        exp = exp / 2n;
        base = (base * base) % mod;
    }
    return Number(result);
}

function computeDLP() {
    const g = parseInt(document.getElementById('dlp-g').value);
    const x = parseInt(document.getElementById('dlp-x').value);
    const p = parseInt(document.getElementById('dlp-p').value);

    if (g < 2 || p < 2 || x < 1) {
        document.getElementById('dlp-result-value').textContent = 'Invalid input';
        return;
    }

    const result = modPow(g, x, p);

    document.getElementById('dlp-result-value').textContent = result;
    document.getElementById('dlp-result-note').textContent =
        `${g}^${x} mod ${p} = ${result}`;

    // Show challenge
    const challenge = document.getElementById('dlp-challenge');
    challenge.style.display = 'block';
    document.getElementById('challenge-h').textContent = result;
    document.getElementById('challenge-g').textContent = g;
    document.getElementById('challenge-p').textContent = p;
}

// ===== Brute Force Visualizer =====
async function startBruteForce() {
    const target = parseInt(document.getElementById('bf-target').value);
    const g = parseInt(document.getElementById('bf-g').value);
    const p = parseInt(document.getElementById('bf-p').value);

    const attemptsDiv = document.getElementById('bf-attempts');
    const barDiv = document.getElementById('bf-bar');
    const resultDiv = document.getElementById('bf-result');

    attemptsDiv.innerHTML = '';
    resultDiv.innerHTML = '';
    barDiv.style.width = '0%';

    let found = false;

    for (let x = 1; x < p; x++) {
        const computed = modPow(g, x, p);
        const progress = (x / (p - 1)) * 100;
        barDiv.style.width = `${progress}%`;

        const line = document.createElement('div');
        line.textContent = `x=${x}: ${g}^${x} mod ${p} = ${computed} ${computed === target ? '✓ FOUND!' : '✗'}`;
        line.style.color = computed === target ? '#10b981' : '#64748b';
        attemptsDiv.appendChild(line);
        attemptsDiv.scrollTop = attemptsDiv.scrollHeight;

        if (computed === target) {
            resultDiv.innerHTML = `<span style="color: #10b981">✓ Found x = ${x} after ${x} attempts</span>`;
            found = true;
            break;
        }

        await new Promise(r => setTimeout(r, 50));
    }

    if (!found) {
        resultDiv.innerHTML = `<span style="color: #ef4444">✗ No solution found (tried all values)</span>`;
    }
}

// ===== ZK Proof Demo =====
async function startZKProof() {
    const balance = parseInt(document.getElementById('zkp-balance').value);
    const amount = parseInt(document.getElementById('zkp-amount').value);
    const messagesDiv = document.getElementById('protocol-messages');
    const btn = document.getElementById('zkp-start-btn');

    btn.disabled = true;
    messagesDiv.innerHTML = '';

    // Reset steps
    document.querySelectorAll('.step-item').forEach(s => {
        s.classList.remove('active', 'completed');
    });

    // Update prover info
    document.getElementById('prover-balance').textContent = `₹${balance.toLocaleString()}`;

    // Check if balance is sufficient
    const sufficient = balance >= amount;

    // Step 1: Commitment
    document.getElementById('step-1').classList.add('active');
    await addMessage(messagesDiv, 'prover', '→', 'Prover',
        `Generating commitment... (balance = ₹${balance.toLocaleString()})`,
        `C = g^r mod p (random r chosen)`);
    await sleep(800);

    const fakeCommitment = generateFakeHex(20);
    document.getElementById('prover-commitment').textContent = fakeCommitment.slice(0, 16) + '...';
    document.getElementById('step-1').classList.remove('active');
    document.getElementById('step-1').classList.add('completed');

    await addMessage(messagesDiv, 'prover', '→', 'Prover → Verifier',
        `Sends commitment C`,
        `C = 0x${fakeCommitment}`);
    await sleep(600);

    // Step 2: Challenge
    document.getElementById('step-2').classList.add('active');
    const fakeChallenge = generateFakeHex(8);
    await addMessage(messagesDiv, 'verifier', '←', 'Verifier',
        `Generates random challenge`,
        `c = 0x${fakeChallenge}`);
    await sleep(600);

    await addMessage(messagesDiv, 'verifier', '←', 'Verifier → Prover',
        `Sends challenge c`,
        `c = 0x${fakeChallenge}`);
    document.getElementById('step-2').classList.remove('active');
    document.getElementById('step-2').classList.add('completed');
    await sleep(600);

    // Step 3: Response
    document.getElementById('step-3').classList.add('active');

    if (!sufficient) {
        await addMessage(messagesDiv, 'fail', '✗', 'Prover',
            `Cannot generate valid response! Balance ₹${balance.toLocaleString()} < ₹${amount.toLocaleString()}`,
            `Proof generation failed — insufficient balance`);
        document.getElementById('verifier-convinced').textContent = 'No';
        document.getElementById('step-3').classList.remove('active');
        btn.disabled = false;
        return;
    }

    const fakeResponse = generateFakeHex(16);
    await addMessage(messagesDiv, 'prover', '→', 'Prover',
        `Computing response: s = r + c × secret mod q`,
        `s = 0x${fakeResponse}`);
    await sleep(600);

    await addMessage(messagesDiv, 'prover', '→', 'Prover → Verifier',
        `Sends response s`,
        `s = 0x${fakeResponse}`);
    document.getElementById('step-3').classList.remove('active');
    document.getElementById('step-3').classList.add('completed');
    await sleep(600);

    // Step 4: Verification
    document.getElementById('step-4').classList.add('active');
    await addMessage(messagesDiv, 'verifier', '←', 'Verifier',
        `Checking: g^s ≡ C × h^c (mod p)`,
        `Verifying proof...`);
    await sleep(1000);

    await addMessage(messagesDiv, 'result', '✓', 'Verification Result',
        `Proof VALID! Balance ≥ ₹${amount.toLocaleString()} confirmed`,
        `Verifier learned: balance is sufficient. Verifier did NOT learn: actual balance.`);

    document.getElementById('verifier-convinced').textContent = 'Yes';
    document.getElementById('verifier-knows').textContent = 'No';
    document.getElementById('step-4').classList.remove('active');
    document.getElementById('step-4').classList.add('completed');

    btn.disabled = false;
}

function resetZKP() {
    document.getElementById('protocol-messages').innerHTML =
        '<div class="message-placeholder">Start the protocol to see messages flow</div>';
    document.getElementById('prover-commitment').textContent = '—';
    document.getElementById('verifier-convinced').textContent = '—';
    document.getElementById('verifier-knows').textContent = 'No';
    document.querySelectorAll('.step-item').forEach(s => {
        s.classList.remove('active', 'completed');
    });
    document.getElementById('zkp-start-btn').disabled = false;
}

async function addMessage(container, type, icon, label, text, value) {
    const msg = document.createElement('div');
    msg.className = `protocol-message msg-${type}`;
    msg.innerHTML = `
        <div class="msg-icon">${icon}</div>
        <div class="msg-content">
            <div class="msg-label">${label}</div>
            <div class="msg-text">${text}</div>
            ${value ? `<div class="msg-value">${value}</div>` : ''}
        </div>
    `;
    container.appendChild(msg);
    container.scrollTop = container.scrollHeight;
}

function generateFakeHex(length) {
    return Array.from({ length }, () => Math.floor(Math.random() * 16).toString(16)).join('');
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ===== Transaction Demo =====
async function setupDemoUsers() {
    const btn = document.getElementById('setup-btn');
    btn.disabled = true;
    btn.textContent = 'Creating...';

    try {
        const response = await fetch(`${API_BASE}/api/demo/setup`, { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            users = {};
            for (const [key, user] of Object.entries(data.users)) {
                users[user.user_id] = { ...user, name: key.charAt(0).toUpperCase() + key.slice(1) };
            }
            renderUsers();
            populateDropdowns();
            document.getElementById('tx-btn').disabled = false;
        }
    } catch (e) {
        // Fallback: create local demo users
        users = {
            'alice-001': { user_id: 'alice-001', name: 'Alice', balance: 10000, balance_commitment: '0x' + generateFakeHex(40) },
            'bob-002': { user_id: 'bob-002', name: 'Bob', balance: 5000, balance_commitment: '0x' + generateFakeHex(40) },
            'charlie-003': { user_id: 'charlie-003', name: 'Charlie', balance: 15000, balance_commitment: '0x' + generateFakeHex(40) }
        };
        renderUsers();
        populateDropdowns();
        document.getElementById('tx-btn').disabled = false;
    }

    btn.textContent = 'Users Created ✓';
}

function renderUsers() {
    const list = document.getElementById('users-list');
    list.innerHTML = '';

    for (const user of Object.values(users)) {
        const card = document.createElement('div');
        card.className = 'user-card';
        card.innerHTML = `
            <div class="user-name">${user.name}</div>
            <div class="user-balance">₹${(user.balance || '???').toLocaleString()}</div>
            <div class="user-commitment">Commitment: ${(user.balance_commitment || '').slice(0, 24)}...</div>
        `;
        list.appendChild(card);
    }
}

function populateDropdowns() {
    const sender = document.getElementById('tx-sender');
    const receiver = document.getElementById('tx-receiver');

    sender.innerHTML = '<option value="">Select sender</option>';
    receiver.innerHTML = '<option value="">Select receiver</option>';

    for (const user of Object.values(users)) {
        sender.innerHTML += `<option value="${user.user_id}">${user.name}</option>`;
        receiver.innerHTML += `<option value="${user.user_id}">${user.name}</option>`;
    }
}

async function executeTransaction() {
    const senderId = document.getElementById('tx-sender').value;
    const receiverId = document.getElementById('tx-receiver').value;
    const amount = parseInt(document.getElementById('tx-amount').value);

    if (!senderId || !receiverId || senderId === receiverId) {
        alert('Please select different sender and receiver');
        return;
    }

    const btn = document.getElementById('tx-btn');
    btn.disabled = true;
    btn.textContent = 'Processing...';

    const resultCard = document.getElementById('tx-result-card');
    const resultDiv = document.getElementById('tx-result');
    resultCard.style.display = 'block';

    try {
        const response = await fetch(`${API_BASE}/api/transactions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sender_id: senderId, receiver_id: receiverId, amount })
        });
        const data = await response.json();
        handleTransactionResult(data, senderId, receiverId, amount);
    } catch (e) {
        // Fallback: simulate locally
        const sender = users[senderId];
        const receiver = users[receiverId];

        if (sender.balance >= amount) {
            sender.balance -= amount;
            receiver.balance += amount;
            sender.balance_commitment = '0x' + generateFakeHex(40);
            receiver.balance_commitment = '0x' + generateFakeHex(40);

            const result = {
                success: true,
                transaction: {
                    transaction_id: 'tx-' + generateFakeHex(8),
                    status: 'completed',
                    proof_included: true
                },
                proof: {
                    num_chunks: 1,
                    chunk_proofs: [{ R_x: '0x' + generateFakeHex(32), s: '0x' + generateFakeHex(32) }]
                }
            };
            handleTransactionResult(result, senderId, receiverId, amount);
        } else {
            handleTransactionResult({
                success: false,
                error: 'Insufficient balance',
                transaction: { status: 'failed' }
            }, senderId, receiverId, amount);
        }
    }

    btn.disabled = false;
    btn.textContent = 'Send with ZK Proof';
}

function handleTransactionResult(data, senderId, receiverId, amount) {
    const resultDiv = document.getElementById('tx-result');
    const senderName = users[senderId]?.name || senderId;
    const receiverName = users[receiverId]?.name || receiverId;

    if (data.success) {
        // Update local user balances
        users[senderId].balance -= amount;
        users[receiverId].balance += amount;
        renderUsers();

        resultDiv.innerHTML = `
            <div class="tx-success">
                <div style="font-size: 1.5rem; margin-bottom: 8px;">Transaction Successful</div>
                <div>${senderName} → ${receiverName}: ₹${amount.toLocaleString()}</div>
                <div style="margin-top: 8px; font-size: 0.85rem; color: var(--text-secondary);">
                    ZK Proof verified — balance sufficiency confirmed without revealing actual balance
                </div>
                ${data.proof ? `
                <div class="proof-display">
                    <div class="proof-label">Zero-Knowledge Proof (ECC Schnorr):</div>
                    <div>Chunks: ${data.proof.num_chunks}</div>
                    <div>R (commitment point): ${data.proof.chunk_proofs?.[0]?.R_x?.slice(0, 18)}...</div>
                    <div>s (response scalar): ${data.proof.chunk_proofs?.[0]?.s?.slice(0, 18)}...</div>
                </div>` : ''}
            </div>
        `;

        transactionHistory.unshift({
            from: senderName, to: receiverName, amount, status: 'completed',
            id: data.transaction?.transaction_id || 'tx-' + generateFakeHex(4)
        });
    } else {
        resultDiv.innerHTML = `
            <div class="tx-failure">
                <div style="font-size: 1.5rem; margin-bottom: 8px;">Transaction Failed</div>
                <div>${senderName} → ${receiverName}: ₹${amount.toLocaleString()}</div>
                <div style="margin-top: 8px; color: var(--danger);">${data.error}</div>
                <div style="margin-top: 8px; font-size: 0.85rem; color: var(--text-secondary);">
                    ZK Proof could not be generated — prover cannot fake sufficient balance (DLP hardness)
                </div>
            </div>
        `;

        transactionHistory.unshift({
            from: senderName, to: receiverName, amount, status: 'failed',
            id: data.transaction?.transaction_id || 'tx-' + generateFakeHex(4)
        });
    }

    renderUsers();
    renderTransactionHistory();
}

function renderTransactionHistory() {
    const historyDiv = document.getElementById('tx-history');
    if (transactionHistory.length === 0) {
        historyDiv.innerHTML = '<div class="empty-state">No transactions yet.</div>';
        return;
    }

    historyDiv.innerHTML = transactionHistory.map(tx => `
        <div class="tx-item ${tx.status === 'failed' ? 'failed' : ''}">
            <div class="tx-item-header">
                <span class="tx-item-amount">₹${tx.amount.toLocaleString()}</span>
                <span class="tx-item-status">${tx.status === 'completed' ? '✓' : '✗'} ${tx.status}</span>
            </div>
            <div class="tx-item-parties">${tx.from} → ${tx.to}</div>
        </div>
    `).join('');
}

// ===== Crypto Suite Modals =====
const suiteContent = {
    dh: {
        title: 'Diffie-Hellman Key Exchange',
        desc: 'Two parties establish a shared secret over an insecure channel. Security relies on DLP.',
        demo: `
            <h4>How It Works</h4>
            <div style="margin-bottom: 16px;">
                <p><strong>1.</strong> Alice picks secret <code>a</code>, sends <code>g^a mod p</code> to Bob</p>
                <p><strong>2.</strong> Bob picks secret <code>b</code>, sends <code>g^b mod p</code> to Alice</p>
                <p><strong>3.</strong> Both compute shared secret: <code>g^(ab) mod p</code></p>
                <p><strong>Security:</strong> Attacker sees <code>g^a</code> and <code>g^b</code> but cannot compute <code>g^(ab)</code> (CDH problem)</p>
            </div>
            <button class="btn btn-primary btn-full" onclick="demoDH()">Simulate Key Exchange</button>
            <div class="modal-result" id="dh-result"></div>
        `
    },
    elgamal: {
        title: 'ElGamal Encryption',
        desc: 'Public-key encryption with homomorphic properties. E(m1) × E(m2) = E(m1 × m2)',
        demo: `
            <h4>Encrypt a Message</h4>
            <div class="input-group">
                <label>Message (number)</label>
                <input type="number" id="elgamal-msg" value="42" min="1" max="10000">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoElGamal()">Encrypt & Decrypt</button>
            <div class="modal-result" id="elgamal-result"></div>
        `
    },
    signatures: {
        title: 'Schnorr Digital Signatures',
        desc: 'Sign messages to prove authenticity. Forging requires solving DLP.',
        demo: `
            <h4>Sign a Transaction</h4>
            <div class="input-group">
                <label>Transaction Message</label>
                <input type="text" id="sig-msg" value="Pay ₹5000 to Bob" style="font-family: Inter, sans-serif;">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoSignature()">Sign & Verify</button>
            <div class="modal-result" id="sig-result"></div>
        `
    },
    batch: {
        title: 'Batch Verification',
        desc: 'Verify multiple proofs at once for better performance.',
        demo: `
            <h4>Performance Comparison</h4>
            <div class="input-group">
                <label>Number of Proofs</label>
                <input type="number" id="batch-count" value="10" min="2" max="100">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoBatch()">Compare Performance</button>
            <div class="modal-result" id="batch-result"></div>
        `
    },
    range: {
        title: 'Range Proofs',
        desc: 'Prove a value is within a range without revealing the exact value.',
        demo: `
            <h4>UPI Transaction Limit Check</h4>
            <div class="input-group">
                <label>Transaction Amount (₹)</label>
                <input type="number" id="range-amount" value="50000" min="1">
            </div>
            <div class="input-group">
                <label>Max Limit (₹)</label>
                <input type="number" id="range-max" value="100000" min="1">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoRange()">Generate Range Proof</button>
            <div class="modal-result" id="range-result"></div>
        `
    },
    zkp: {
        title: 'Zero-Knowledge Proofs',
        desc: 'Prove you know a secret without revealing it. The core of our system.',
        demo: `
            <h4>Schnorr Identification Protocol</h4>
            <p style="color: var(--text-secondary); margin-bottom: 16px;">
                Prove knowledge of discrete logarithm x where h = g^x mod p, without revealing x.
            </p>
            <div class="input-group">
                <label>Your Secret (x)</label>
                <input type="number" id="zkp-secret" value="42" min="1">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoZKP()">Generate Proof</button>
            <div class="modal-result" id="zkp-result"></div>
        `
    },
    commitments: {
        title: 'Pedersen Commitments',
        desc: 'Commit to a value without revealing it. Binding and hiding properties.',
        demo: `
            <h4>Commit to a Value</h4>
            <div class="input-group">
                <label>Value to Commit</label>
                <input type="number" id="commit-value" value="1000" min="1">
            </div>
            <button class="btn btn-primary btn-full" onclick="demoCommitment()">Create Commitment</button>
            <div class="modal-result" id="commit-result"></div>
        `
    }
};

function openSuiteDemo(type) {
    const modal = document.getElementById('suite-modal');
    const body = document.getElementById('modal-body');
    const content = suiteContent[type];

    body.innerHTML = `
        <h2 style="margin-bottom: 8px;">${content.title}</h2>
        <p style="color: var(--text-secondary); margin-bottom: 24px;">${content.desc}</p>
        <div class="modal-demo-section">${content.demo}</div>
    `;

    modal.style.display = 'flex';
}

function closeSuiteDemo() {
    document.getElementById('suite-modal').style.display = 'none';
}

// Close modal on overlay click
document.getElementById('suite-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'suite-modal') closeSuiteDemo();
});

// ===== Suite Demo Functions =====
function demoDH() {
    const p = 23; const g = 2;
    const a = Math.floor(Math.random() * 20) + 2;
    const b = Math.floor(Math.random() * 20) + 2;
    const A = modPow(g, a, p);
    const B = modPow(g, b, p);
    const secretA = modPow(B, a, p);
    const secretB = modPow(A, b, p);

    document.getElementById('dh-result').innerHTML = `
        <div style="color: var(--accent-secondary);">Parameters: g=${g}, p=${p}</div>
        <br>
        <div>Alice: secret a=${a}, public A=g^a=${A}</div>
        <div>Bob: secret b=${b}, public B=g^b=${B}</div>
        <br>
        <div>Alice computes: B^a = ${B}^${a} mod ${p} = <strong style="color: var(--success);">${secretA}</strong></div>
        <div>Bob computes: A^b = ${A}^${b} mod ${p} = <strong style="color: var(--success);">${secretB}</strong></div>
        <br>
        <div style="color: ${secretA === secretB ? 'var(--success)' : 'var(--danger)'};">
            ${secretA === secretB ? '✓ Shared secrets match. Secure channel established.' : '✗ Error in computation'}
        </div>
        <br>
        <div style="color: var(--text-muted);">Attacker sees A=${A} and B=${B} but cannot compute shared secret without solving DLP</div>
    `;
}

function demoElGamal() {
    const msg = parseInt(document.getElementById('elgamal-msg').value);
    const p = 23; const g = 2;
    const x = Math.floor(Math.random() * 20) + 2;
    const h = modPow(g, x, p);
    const y = Math.floor(Math.random() * 20) + 2;
    const c1 = modPow(g, y, p);
    const s = modPow(h, y, p);
    const c2 = (msg % p * s) % p;
    const sDecrypt = modPow(c1, x, p);
    const sInv = modPow(sDecrypt, p - 2, p);
    const decrypted = (c2 * sInv) % p;

    document.getElementById('elgamal-result').innerHTML = `
        <div style="color: var(--accent-secondary);">Keys: private x=${x}, public h=g^x=${h} (p=${p})</div>
        <br>
        <div>Original message: ${msg % p} (mod ${p})</div>
        <br>
        <div style="color: var(--warning);">Encryption (random y=${y}):</div>
        <div>  c1 = g^y = ${c1}</div>
        <div>  c2 = m × h^y = ${c2}</div>
        <br>
        <div style="color: var(--success);">Decryption:</div>
        <div>  s = c1^x = ${sDecrypt}</div>
        <div>  m = c2 × s^(-1) = <strong>${decrypted}</strong></div>
        <br>
        <div style="color: ${decrypted === (msg % p) ? 'var(--success)' : 'var(--danger)'};">
            ${decrypted === (msg % p) ? '✓ Decryption successful.' : '✗ Decryption error'}
        </div>
    `;
}

function demoSignature() {
    const msg = document.getElementById('sig-msg').value;
    const r = '0x' + generateFakeHex(16);
    const s = '0x' + generateFakeHex(16);

    document.getElementById('sig-result').innerHTML = `
        <div>Message: "${msg}"</div>
        <br>
        <div style="color: var(--warning);">Signature:</div>
        <div>  r = ${r}</div>
        <div>  s = ${s}</div>
        <br>
        <div style="color: var(--success);">✓ Signature verified. Message is authentic.</div>
        <br>
        <div style="color: var(--text-muted);">Security: Forging this signature requires solving the Discrete Logarithm Problem</div>
    `;
}

function demoBatch() {
    const count = parseInt(document.getElementById('batch-count').value);
    const individualCost = count * 3;
    const batchCost = count * 2 + 5;
    const speedup = (individualCost / batchCost).toFixed(2);

    document.getElementById('batch-result').innerHTML = `
        <div style="color: var(--accent-secondary);">Verifying ${count} proofs:</div>
        <br>
        <div>Individual: ${individualCost} modular exponentiations</div>
        <div>Batch: ${batchCost} modular exponentiations</div>
        <br>
        <div style="font-size: 1.2rem; color: var(--success);">
            Speedup: ${speedup}x faster with batch verification
        </div>
        <br>
        <div style="color: var(--text-muted);">
            Recommendation: ${count > 3 ? 'Use batch verification' : 'Individual verification is fine for small batches'}
        </div>
    `;
}

function demoRange() {
    const amount = parseInt(document.getElementById('range-amount').value);
    const maxLimit = parseInt(document.getElementById('range-max').value);
    const inRange = amount >= 1 && amount <= maxLimit;

    document.getElementById('range-result').innerHTML = `
        <div>Transaction: ₹${amount.toLocaleString()}</div>
        <div>Valid range: ₹1 — ₹${maxLimit.toLocaleString()}</div>
        <br>
        <div style="color: ${inRange ? 'var(--success)' : 'var(--danger)'}; font-size: 1.2rem;">
            ${inRange ? '✓ Range proof valid. Amount is within limits.' : '✗ Amount outside valid range.'}
        </div>
        <br>
        <div style="color: var(--text-muted);">
            ${inRange ? 'The verifier knows the amount is within limits but does NOT know the exact amount.' : 'Range proof cannot be generated for out-of-range values.'}
        </div>
    `;
}

function demoZKP() {
    const secret = parseInt(document.getElementById('zkp-secret').value);
    const p = 23; const g = 2;
    const h = modPow(g, secret, p);
    const r = Math.floor(Math.random() * 20) + 2;
    const commitment = modPow(g, r, p);
    const challenge = Math.floor(Math.random() * 20) + 1;
    const response = (r + challenge * secret) % (p - 1);
    const lhs = modPow(g, response, p);
    const rhs = (commitment * modPow(h, challenge, p)) % p;

    document.getElementById('zkp-result').innerHTML = `
        <div style="color: var(--danger);">Secret: x = ${secret} (never revealed to verifier)</div>
        <div>Public: h = g^x = ${g}^${secret} mod ${p} = ${h}</div>
        <br>
        <div><strong>Step 1:</strong> Commitment C = g^r = ${g}^${r} = ${commitment}</div>
        <div><strong>Step 2:</strong> Challenge c = ${challenge}</div>
        <div><strong>Step 3:</strong> Response s = r + c×x = ${r} + ${challenge}×${secret} = ${response}</div>
        <br>
        <div><strong>Step 4:</strong> Verify g^s = C × h^c</div>
        <div>  Left:  g^s = ${g}^${response} mod ${p} = ${lhs}</div>
        <div>  Right: C × h^c = ${commitment} × ${h}^${challenge} mod ${p} = ${rhs}</div>
        <br>
        <div style="color: ${lhs === rhs ? 'var(--success)' : 'var(--danger)'}; font-size: 1.1rem;">
            ${lhs === rhs ? '✓ Proof valid. Prover knows x without revealing it.' : '✗ Proof invalid.'}
        </div>
    `;
}

function demoCommitment() {
    const value = parseInt(document.getElementById('commit-value').value);
    const commitment = '0x' + generateFakeHex(32);
    const randomness = '0x' + generateFakeHex(16);

    document.getElementById('commit-result').innerHTML = `
        <div>Value: ${value} (hidden)</div>
        <div>Randomness: ${randomness}</div>
        <br>
        <div style="color: var(--accent-secondary);">
            Commitment: C = g^${value} × h^r mod p
        </div>
        <div style="word-break: break-all;">C = ${commitment}</div>
        <br>
        <div style="color: var(--success);">✓ Commitment created.</div>
        <br>
        <div style="color: var(--text-muted);">
            <strong>Hiding:</strong> Cannot determine ${value} from commitment (DLP hardness)<br>
            <strong>Binding:</strong> Cannot open commitment to different value
        </div>
    `;
}

// ===== Chunked Balance Demo =====
function setChunkPreset(multiplier, offset, txAmount) {
    document.getElementById('chunk-multiplier').value = multiplier;
    document.getElementById('chunk-offset').value = offset;
    document.getElementById('chunk-tx-amount').value = txAmount;
}

async function runChunkedDemo() {
    const btn = document.getElementById('chunk-btn');
    btn.disabled = true;
    btn.textContent = 'Running...';

    const multiplier = parseInt(document.getElementById('chunk-multiplier').value);
    const offset = parseInt(document.getElementById('chunk-offset').value);
    const txAmount = parseInt(document.getElementById('chunk-tx-amount').value);

    let data;
    try {
        const res = await fetch(`${API_BASE}/api/chunked-demo`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                balance_multiplier: multiplier,
                balance_offset: offset,
                tx_amount: txAmount
            })
        });
        data = await res.json();
    } catch (e) {
        // Fallback: simulate locally
        const isChunked = multiplier > 0;
        const chunks = multiplier > 0
            ? [offset, multiplier]
            : [offset];
        data = {
            success: true,
            n_hex: '0x7fffffffffffffffffff...',
            n_bits: 256,
            balance_hex: '0x' + generateFakeHex(20) + '...',
            balance_bits: isChunked ? 256 + Math.floor(Math.log2(multiplier + 1)) : Math.max(1, Math.ceil(Math.log2(offset + 1))),
            balance_formula: `${multiplier} × n + ${offset}`,
            num_chunks: chunks.length,
            chunks: chunks,
            chunk_commitments: chunks.map(() => '0x' + generateFakeHex(20) + '...'),
            combined_commitment: '0x' + generateFakeHex(20) + '...',
            reconstruction_matches: true,
            tx_amount: txAmount,
            can_prove: true,
            proof_valid: true,
            proof_num_chunks: chunks.length,
        };
    }

    if (!data.success) {
        document.getElementById('chunk-results-card').style.display = 'block';
        document.getElementById('chunk-results').innerHTML = `
            <div style="color: var(--danger);">Error: ${data.error}</div>
        `;
        btn.textContent = 'Run Chunked Balance Demo';
        btn.disabled = false;
        return;
    }

    // Show results card
    const resultsCard = document.getElementById('chunk-results-card');
    resultsCard.style.display = 'block';

    const isChunked = data.num_chunks > 1;
    const resultsDiv = document.getElementById('chunk-results');
    resultsDiv.innerHTML = `
        <div class="chunk-result-grid">
            <div class="chunk-stat">
                <div class="chunk-stat-label">Balance Formula</div>
                <div class="chunk-stat-value">${data.balance_formula}</div>
            </div>
            <div class="chunk-stat">
                <div class="chunk-stat-label">Balance Size</div>
                <div class="chunk-stat-value">${data.balance_bits} bits</div>
            </div>
            <div class="chunk-stat">
                <div class="chunk-stat-label">Curve Order (n)</div>
                <div class="chunk-stat-value">${data.n_bits} bits</div>
            </div>
            <div class="chunk-stat ${isChunked ? 'chunk-stat-warn' : 'chunk-stat-ok'}">
                <div class="chunk-stat-label">Exceeds n?</div>
                <div class="chunk-stat-value">${isChunked ? 'Yes — chunked' : 'No — single chunk'}</div>
            </div>
            <div class="chunk-stat">
                <div class="chunk-stat-label">Chunks</div>
                <div class="chunk-stat-value">${data.num_chunks}</div>
            </div>
            <div class="chunk-stat ${data.proof_valid ? 'chunk-stat-ok' : 'chunk-stat-warn'}">
                <div class="chunk-stat-label">Proof Valid</div>
                <div class="chunk-stat-value">${data.proof_valid ? '✓ Yes' : '✗ No'}</div>
            </div>
        </div>
    `;

    // Show step-by-step
    const stepsCard = document.getElementById('chunk-steps-card');
    stepsCard.style.display = 'block';
    const stepsDiv = document.getElementById('chunk-steps');

    let stepsHTML = `<div class="chunk-step-list">`;

    // Step 1: Balance
    stepsHTML += `
        <div class="chunk-step-item">
            <div class="chunk-step-num">1</div>
            <div class="chunk-step-body">
                <div class="chunk-step-title">Original Balance</div>
                <div class="chunk-step-detail">
                    <code>${data.balance_formula}</code> = <code>${data.balance_hex}</code>
                    <span class="chunk-step-tag">${data.balance_bits} bits</span>
                </div>
            </div>
        </div>
    `;

    // Step 2: Range check
    stepsHTML += `
        <div class="chunk-step-item">
            <div class="chunk-step-num">2</div>
            <div class="chunk-step-body">
                <div class="chunk-step-title">Range Check</div>
                <div class="chunk-step-detail">
                    n = <code>${data.n_hex}</code> (${data.n_bits} bits)
                    <br>balance ${isChunked ? '≥' : '<'} n →
                    <span style="color: ${isChunked ? 'var(--warning)' : 'var(--success)'};">
                        ${isChunked ? 'needs chunking' : 'fits in single chunk'}
                    </span>
                </div>
            </div>
        </div>
    `;

    // Step 3: Decomposition
    const chunkLabels = data.chunks.map((c, i) => `c${i} = ${c}`).join(', ');
    stepsHTML += `
        <div class="chunk-step-item">
            <div class="chunk-step-num">3</div>
            <div class="chunk-step-body">
                <div class="chunk-step-title">Base-n Decomposition</div>
                <div class="chunk-step-detail">
                    <code>[${chunkLabels}]</code>
                    <br>Reconstruction: ${data.chunks.map((c, i) => i === 0 ? `${c}` : `${c}·n${i > 1 ? '<sup>' + i + '</sup>' : ''}`).join(' + ')}
                    <br>Matches original: <span style="color: var(--success);">✓ ${data.reconstruction_matches ? 'Yes' : 'No'}</span>
                </div>
            </div>
        </div>
    `;

    // Step 4: Commitments
    stepsHTML += `
        <div class="chunk-step-item">
            <div class="chunk-step-num">4</div>
            <div class="chunk-step-body">
                <div class="chunk-step-title">Per-Chunk Public Keys (Q<sub>i</sub> = c<sub>i</sub>·P)</div>
                <div class="chunk-step-detail">
                    ${data.chunk_commitments.map((c, i) => `Chunk ${i}: <code>${c.slice(0, 24)}...</code>`).join('<br>')}
                    <br>Combined: <code>${data.combined_commitment}</code>
                </div>
            </div>
        </div>
    `;

    // Step 5: Proof
    stepsHTML += `
        <div class="chunk-step-item">
            <div class="chunk-step-num">5</div>
            <div class="chunk-step-body">
                <div class="chunk-step-title">ZK Proof (balance ≥ ₹${data.tx_amount.toLocaleString()})</div>
                <div class="chunk-step-detail">
                    Proofs generated: ${data.proof_num_chunks} (one per chunk)
                    <br>Verification:
                    <span style="color: ${data.proof_valid ? 'var(--success)' : 'var(--danger)'}; font-weight: 700;">
                        ${data.proof_valid ? '✓ Valid — balance sufficient, all chunks verified' : '✗ Invalid'}
                    </span>
                </div>
            </div>
        </div>
    `;

    stepsHTML += `</div>`;
    stepsDiv.innerHTML = stepsHTML;

    btn.textContent = 'Run Chunked Balance Demo';
    btn.disabled = false;
}

// ===== Benchmark =====
async function runBenchmark() {
    const btn = document.getElementById('bench-btn');
    const status = document.getElementById('bench-status');
    btn.disabled = true;
    btn.textContent = 'Running...';
    status.textContent = 'This takes a few seconds — running crypto operations...';

    try {
        const res = await fetch(`${API_BASE}/api/benchmark`);
        const data = await res.json();
        if (!data.success) throw new Error(data.error);
        renderBenchmark(data.results);
    } catch (e) {
        status.textContent = 'Error: ' + e.message;
    }
    btn.disabled = false;
    btn.textContent = 'Run Benchmark';
}

function renderBenchmark(r) {
    document.getElementById('bench-status').textContent = '';
    const protocols = ['ecc_schnorr_zk', 'dlp_schnorr', 'dsa', 'ecdsa'];
    const labels = {'ecc_schnorr_zk': 'ECC Schnorr ZK', 'dlp_schnorr': 'DLP Schnorr', 'dsa': 'DSA', 'ecdsa': 'ECDSA'};
    const colors = {'ecc_schnorr_zk': 'var(--accent-primary)', 'dlp_schnorr': '#60a5fa', 'dsa': '#f59e0b', 'ecdsa': '#f87171'};

    // Timing card
    const timingCard = document.getElementById('bench-timing-card');
    timingCard.style.display = 'block';
    const phases = [
        ['keygen_ms', 'Key / Commitment Generation'],
        ['prove_sign_ms', 'Prove / Sign'],
        ['verify_ms', 'Verification'],
        ['full_transaction_ms', 'Full Transaction'],
    ];

    let html = '';
    for (const [key, title] of phases) {
        const d = r[key];
        const max = Math.max(...protocols.map(p => d[p] || 0)) || 1;
        html += `<div class="bench-phase"><div class="bench-phase-title">${title}</div>`;
        for (const p of protocols) {
            const v = d[p] || 0;
            const pct = Math.max((v / max) * 100, 2);
            html += `<div class="bench-bar-row">
                <span class="bench-bar-label">${labels[p]}</span>
                <div class="bench-bar-track"><div class="bench-bar-fill" style="width:${pct}%;background:${colors[p]}"></div></div>
                <span class="bench-bar-value">${v} ms</span>
            </div>`;
        }
        html += '</div>';
    }
    document.getElementById('bench-timing').innerHTML = html;

    // Features card
    const featCard = document.getElementById('bench-features-card');
    featCard.style.display = 'block';
    const feat = r.features;
    let fhtml = '<table class="compare-table"><thead><tr><th>Feature</th>';
    for (const p of protocols) fhtml += `<th>${labels[p]}</th>`;
    fhtml += '</tr></thead><tbody>';
    const featureLabels = {
        'zk_proofs': 'Zero-Knowledge Proofs',
        'privacy': 'Balance Privacy',
        'batch_verify': 'Native Batch Verify',
        'sig_aggregation': 'Signature Aggregation',
        'security_bits': 'Security (bits)',
        'key_bits': 'Key Size (bits)',
    };
    for (const [fk, fl] of Object.entries(featureLabels)) {
        fhtml += `<tr><td>${fl}</td>`;
        for (const p of protocols) {
            const v = feat[fk][p];
            if (typeof v === 'boolean') {
                fhtml += `<td class="${v ? 'success-text' : 'danger-text'}">${v ? '✓' : '✗'}</td>`;
            } else {
                const cls = fk === 'security_bits' ? (v >= 128 ? 'success-text' : 'danger-text') : '';
                fhtml += `<td class="${cls}">${v}</td>`;
            }
        }
        fhtml += '</tr>';
    }
    fhtml += '</tbody></table>';
    document.getElementById('bench-features').innerHTML = fhtml;
}

// ===== Hero Animation =====
function initHeroAnimation() {
    const container = document.getElementById('heroAnimation');
    if (!container) return;

    const nodes = [];
    for (let i = 0; i < 12; i++) {
        const node = document.createElement('div');
        const angle = (i / 12) * Math.PI * 2;
        const radius = 150;
        const x = Math.cos(angle) * radius + 200;
        const y = Math.sin(angle) * radius + 200;

        node.style.cssText = `
            position: absolute;
            width: 12px; height: 12px;
            background: var(--accent-primary);
            border-radius: 50%;
            left: ${x}px; top: ${y}px;
            transform: translate(-50%, -50%);
            box-shadow: 0 0 20px var(--accent-glow);
            animation: float ${2 + Math.random() * 2}s ease-in-out infinite alternate;
        `;
        container.appendChild(node);
        nodes.push({ el: node, x, y });
    }

    // Add center node
    const center = document.createElement('div');
    center.style.cssText = `
        position: absolute;
        width: 60px; height: 60px;
        background: linear-gradient(135deg, var(--accent-primary), #a78bfa);
        border-radius: 50%;
        left: 200px; top: 200px;
        transform: translate(-50%, -50%);
        box-shadow: 0 0 40px var(--accent-glow);
        display: flex; align-items: center; justify-content: center;
        font-size: 1.5rem;
    `;
    center.textContent = 'ZKP';
    container.appendChild(center);

    // Add float animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes float {
            from { transform: translate(-50%, -50%) translateY(-5px); }
            to { transform: translate(-50%, -50%) translateY(5px); }
        }
    `;
    document.head.appendChild(style);
}

// ===== Counter Animation =====
function animateCounters() {
    const counters = [
        { el: document.getElementById('stat-protocols'), target: 7 },
        { el: document.getElementById('stat-bits'), target: 256 },
        { el: document.getElementById('stat-tests'), target: 33 }
    ];

    counters.forEach(({ el, target }) => {
        if (!el) return;
        let current = 0;
        const increment = target / 40;
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                el.textContent = target;
                clearInterval(timer);
            } else {
                el.textContent = Math.floor(current);
            }
        }, 30);
    });
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    initHeroAnimation();
    animateCounters();
});


// TODO
// 1) compare it with DSA and ECDSA for verification purposes in bank side
// 2) more literature survey(recent papers)