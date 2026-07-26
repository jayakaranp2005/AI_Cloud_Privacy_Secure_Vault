/**
 * PrivaVault — main.js
 * Handles: login/register form submission, upload via fetch, tag filter panel, download
 * No external libraries. No token in localStorage.
 */
document.addEventListener('DOMContentLoaded', () => {

    // --- Login form ---
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const errEl = document.getElementById('login-error');
            errEl.style.display = 'none';
            const btn = document.getElementById('login-btn');
            btn.disabled = true;
            try {
                const res = await fetch('/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: loginForm.querySelector('#email').value,
                        password: loginForm.querySelector('#password').value,
                    }),
                });
                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Login failed');
                }
                window.location.href = '/dashboard';
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
                btn.disabled = false;
            }
        });
    }

    // --- Register form ---
    const regForm = document.getElementById('register-form');
    if (regForm) {
        regForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const errEl = document.getElementById('register-error');
            const successEl = document.getElementById('register-success');
            errEl.style.display = 'none';
            successEl.style.display = 'none';
            const pw = regForm.querySelector('#password').value;
            const cpw = regForm.querySelector('#confirm-password').value;
            if (pw !== cpw) {
                errEl.textContent = 'Passwords do not match';
                errEl.style.display = 'block';
                return;
            }
            const btn = document.getElementById('register-btn');
            btn.disabled = true;
            try {
                const res = await fetch('/auth/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: regForm.querySelector('#email').value,
                        password: pw,
                    }),
                });
                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Registration failed');
                }
                successEl.textContent = 'Account created! Redirecting to login...';
                successEl.style.display = 'block';
                setTimeout(() => { window.location.href = '/login'; }, 1500);
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
                btn.disabled = false;
            }
        });
    }

    // --- Upload form ---
    const uploadForm = document.getElementById('upload-form');
    if (uploadForm) {
        const fileInput = document.getElementById('file');
        const fileLabel = document.getElementById('file-label');
        const dropZone = document.getElementById('file-drop-zone');

        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) {
                fileLabel.querySelector('span').textContent = fileInput.files[0].name;
                fileLabel.classList.add('has-file');
            }
        });

        ['dragover', 'dragenter'].forEach(ev =>
            dropZone.addEventListener(ev, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); })
        );
        ['dragleave', 'drop'].forEach(ev =>
            dropZone.addEventListener(ev, () => dropZone.classList.remove('dragover'))
        );

        uploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const errEl = document.getElementById('upload-error');
            errEl.style.display = 'none';
            const btn = document.getElementById('upload-btn');
            btn.querySelector('.btn-text').style.display = 'none';
            btn.querySelector('.btn-loading').style.display = 'inline-flex';
            btn.disabled = true;
            try {
                const fd = new FormData();
                fd.append('file', fileInput.files[0]);
                fd.append('password', uploadForm.querySelector('#password').value);
                const res = await fetch('/vault/upload', { method: 'POST', body: fd });
                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Upload failed');
                }
                window.location.href = '/dashboard';
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
                btn.querySelector('.btn-text').style.display = 'inline';
                btn.querySelector('.btn-loading').style.display = 'none';
                btn.disabled = false;
            }
        });
    }

    // --- Tag filter panel (dashboard) ---
    const tagPanel = document.getElementById('tag-panel');
    if (tagPanel) {
        const searchInput = document.getElementById('tag-search-input');
        const pills = tagPanel.querySelectorAll('.tag-pill');

        // Filter pills as user types in search
        searchInput.addEventListener('input', () => {
            const val = searchInput.value.toLowerCase();
            pills.forEach(pill => {
                const matches = pill.dataset.tag.toLowerCase().includes(val);
                pill.classList.toggle('hidden', !matches);
            });
        });

        // Toggle tag selection on click
        pills.forEach(pill => {
            pill.addEventListener('click', () => {
                pill.classList.toggle('active');
                // Collect all active tags and navigate
                const activeTags = [...tagPanel.querySelectorAll('.tag-pill.active')]
                    .map(p => p.dataset.tag);
                const q = activeTags.join(',');
                window.location.href = q ? `/dashboard?q=${encodeURIComponent(q)}` : '/dashboard';
            });
        });
    }

    // --- Download modal ---
    const downloadModal = document.getElementById('download-modal');
    if (downloadModal) {
        const form = document.getElementById('download-form');
        const docIdInput = document.getElementById('download-doc-id');
        const passwordInput = document.getElementById('download-password');
        const filenameEl = document.getElementById('modal-filename');
        const errEl = document.getElementById('download-error');
        const cancelBtn = document.getElementById('download-cancel');
        const submitBtn = document.getElementById('download-submit-btn');

        // Open modal when download button clicked
        document.querySelectorAll('.btn-download').forEach(btn => {
            btn.addEventListener('click', () => {
                docIdInput.value = btn.dataset.docId;
                filenameEl.textContent = btn.dataset.filename;
                errEl.style.display = 'none';
                passwordInput.value = '';
                downloadModal.style.display = 'flex';
                passwordInput.focus();
            });
        });

        // Close modal
        cancelBtn.addEventListener('click', () => { downloadModal.style.display = 'none'; });
        downloadModal.addEventListener('click', (e) => {
            if (e.target === downloadModal) downloadModal.style.display = 'none';
        });

        // Submit download
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            errEl.style.display = 'none';
            submitBtn.querySelector('.btn-text').style.display = 'none';
            submitBtn.querySelector('.btn-loading').style.display = 'inline-flex';
            submitBtn.disabled = true;
            try {
                const fd = new FormData();
                fd.append('password', passwordInput.value);
                const res = await fetch(`/vault/download/${docIdInput.value}`, {
                    method: 'POST',
                    body: fd,
                });
                if (!res.ok) {
                    const data = await res.json();
                    throw new Error(data.detail || 'Download failed');
                }
                // Stream file download
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filenameEl.textContent;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                downloadModal.style.display = 'none';
            } catch (err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
            } finally {
                submitBtn.querySelector('.btn-text').style.display = 'inline';
                submitBtn.querySelector('.btn-loading').style.display = 'none';
                submitBtn.disabled = false;
            }
        });
    }
});
