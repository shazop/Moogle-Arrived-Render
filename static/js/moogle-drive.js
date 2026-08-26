let currentFiles = [];

document.addEventListener('DOMContentLoaded', () => {
  loadFiles();
  setupDragAndDrop();
  setupGlobalEvents();
});

function loadFiles(query = '') {
  const url = query ? `/drive/v2/files?q=${encodeURIComponent(query)}` : '/drive/v2/files';
  fetch(url)
    .then(r => {
      if (r.status === 401) {
        window.location.href = '/login';
        return null;
      }
      return r.json();
    })
    .then(data => {
      if (!data) return;
      currentFiles = data.items || [];
      renderFiles(currentFiles);
      updateStorageInfo(data.quota || {});
    })
    .catch(err => {
      showToast('⚠ Error loading files: ' + err.message);
    });
}

function updateStorageInfo(quota) {
  const usedBytes = quota.usedBytes || 0;
  const maxBytes = quota.maxBytes || (10 * 1024 * 1024);
  const fileCount = quota.fileCount || currentFiles.length;
  const maxFiles = quota.maxFiles || 5;

  const usedMB = (usedBytes / (1024 * 1024)).toFixed(2);
  const maxMB = (maxBytes / (1024 * 1024)).toFixed(0);
  const percentage = Math.min((usedBytes / maxBytes) * 100, 100).toFixed(1);

  const countBadge = document.getElementById('fileCountBadge');
  const storageText = document.getElementById('storageText');
  const storageFill = document.getElementById('storageFill');

  if (countBadge) countBadge.textContent = `${fileCount} / ${maxFiles} files`;
  if (storageText) storageText.textContent = `${usedMB} MB of ${maxMB} MB used (${fileCount}/${maxFiles} files)`;
  if (storageFill) storageFill.style.width = `${percentage}%`;
}

function renderFiles(files) {
  const container = document.getElementById('filesContainer');
  if (!container) return;

  if (files.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 60px 0; color: var(--text-muted);">
        <div style="font-size: 48px; margin-bottom: 12px;">📁</div>
        <p style="font-size: 15px; color: var(--text-secondary); margin-bottom: 6px;">Your Drive is empty</p>
        <p style="font-size: 13px;">Upload a file or import from URL (up to 5 files, 10 MB total).</p>
      </div>`;
    return;
  }

  container.innerHTML = '';
  files.forEach(f => {
    const card = document.createElement('div');
    card.className = 'file-card';
    card.dataset.fileId = f.id;

    const iconSvg = getFileIconSvg(f.mimeType, f.title);

    card.innerHTML = `
      <div class="file-card-top" ondblclick="openPreviewLightbox('${f.id}', '${escapeHtml(f.title)}')">
        <div class="file-icon-box">${iconSvg}</div>
        <div class="file-card-info">
          <span class="file-card-name" title="${f.title}">${escapeHtml(f.title)}</span>
          <span class="file-card-meta">${f.humanSize || '—'} · ${formatDate(f.modifiedDate)}</span>
        </div>
      </div>

      <div class="file-card-links" style="padding: 0 14px 8px; font-size: 11.5px; display: flex; gap: 10px;">
        <a href="${f.webViewLink || '#'}" class="drive-ext-link" target="_blank" style="color:#1a73e8;text-decoration:none;">View Link</a>
        <a href="${f.webContentLink || '#'}" class="drive-ext-link" target="_blank" style="color:#1a73e8;text-decoration:none;">Content Link</a>
      </div>

      <div class="file-card-actions">
        <button class="btn-card-action" onclick="openPreviewLightbox('${f.id}', '${escapeHtml(f.title)}')">
          <span>Preview</span>
        </button>
        <button class="btn-card-action" onclick="requestAdminReview('${f.id}', '${escapeHtml(f.title)}')" title="Send to admin bot for preview">
          <span>Review</span>
        </button>
        <button class="btn-card-action" onclick="downloadFile('${f.id}')">
          <span>Download</span>
        </button>
        <button class="btn-card-action danger" onclick="deleteFile('${f.id}', '${escapeHtml(f.title)}')" title="Delete file">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="#c5221f"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
        </button>
      </div>
    `;

    container.appendChild(card);
  });
}

function getFileIconSvg(mimeType, title = '') {
  const ext = title.split('.').pop().toLowerCase();

  if (mimeType.includes('pdf') || ext === 'pdf') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#ea4335"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm4-3H19v1h1.5V11H19v2h-1.5V7h3v1.5zM9 9.5h1v-1H9v1zm4.5 2h1v-3h-1v3z"/></svg>`;
  }
  if (mimeType.includes('html') || ext === 'html') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#e44d26"><path d="M12 2L2 7l10 5 10-5-10-5zm0 9l-8-4 8-4 8 4-8 4zm-8 4l8 4 8-4v-2l-8 4-8-4v2zm0 4l8 4 8-4v-2l-8 4-8-4v2z"/></svg>`;
  }
  if (mimeType.includes('svg') || ext === 'svg') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#ff9800"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z"/></svg>`;
  }
  if (mimeType.includes('presentation') || ext === 'pptx') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#fbbc04"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z"/></svg>`;
  }
  if (mimeType.includes('spreadsheet') || ext === 'xlsx') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#34a853"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-2h2v2zm0-4H7v-2h2v2zm0-4H7V7h2v2zm4 8h-2v-2h2v2zm0-4h-2v-2h2v2zm0-4h-2V7h2v2zm4 8h-2v-2h2v2zm0-4h-2v-2h2v2zm0-4h-2V7h2v2z"/></svg>`;
  }
  if (mimeType.startsWith('image/') || ['png','jpg','jpeg','webp','gif'].includes(ext)) {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#e37400"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>`;
  }
  if (mimeType.includes('json') || ext === 'json') {
    return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#1a73e8"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
  }
  return `<svg width="22" height="22" viewBox="0 0 24 24" fill="#5f6368"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
}

function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  } catch { return ''; }
}

function downloadFile(fileId) {
  window.location.href = `/drive/v2/download/${fileId}`;
}

function deleteFile(fileId, filename) {
  if (!confirm(`Are you sure you want to delete "${filename}"?`)) return;

  fetch('/api/drive/delete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileId })
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        showToast(`✓ Deleted "${filename}"`);
        loadFiles();
      } else {
        showToast('⚠ Error: ' + (data.error || 'Could not delete file'));
      }
    })
    .catch(err => {
      showToast('⚠ Error: ' + err.message);
    });
}

function requestAdminReview(fileId, filename) {
  fetch('/api/drive/admin-preview', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileId })
  })
    .then(r => r.json())
    .then(data => {
      if (data.success) {
        showToast(`✓ ${data.message}`);
      } else {
        showToast('⚠ ' + (data.error || 'Review request failed'));
      }
    })
    .catch(err => {
      showToast('⚠ Review request failed: ' + err.message);
    });
}

function filterFiles(query) {
  loadFiles(query.trim());
}

function openPreviewLightbox(fileId, filename) {
  const lightbox = document.getElementById('previewLightbox');
  const titleEl = document.getElementById('plFilename');
  const loading = document.getElementById('plLoading');
  const htmlContent = document.getElementById('plHtmlContent');
  const dlBtn = document.getElementById('plDownloadBtn');
  const reviewBtn = document.getElementById('plAdminReviewBtn');

  titleEl.textContent = filename || 'Document Preview';
  loading.style.display = 'flex';
  htmlContent.style.display = 'none';
  htmlContent.innerHTML = '';
  lightbox.style.display = 'flex';

  dlBtn.onclick = () => downloadFile(fileId);
  reviewBtn.onclick = () => requestAdminReview(fileId, filename);

  fetch(`/api/drive/fetch?file_id=${encodeURIComponent(fileId)}`)
    .then(r => r.json())
    .then(data => {
      loading.style.display = 'none';
      htmlContent.style.display = 'block';
      if (data.success) {
        const raw = data.preview || '';
        
        let linkBar = '';
        if (data.webViewLink || data.webContentLink) {
          linkBar = `
            <div class="pl-links-bar" style="margin-bottom:14px;padding:8px 12px;background:#f1f3f4;border-radius:8px;font-size:12px;display:flex;gap:12px;align-items:center;">
              <span style="color:#5f6368"><strong>Drive Links:</strong></span>
              ${data.webViewLink ? `<a href="${data.webViewLink}" class="drive-ext-link" target="_blank" style="color:#1a73e8;text-decoration:none">🔗 webViewLink</a>` : ''}
              ${data.webContentLink ? `<a href="${data.webContentLink}" class="drive-ext-link" target="_blank" style="color:#1a73e8;text-decoration:none">📥 webContentLink</a>` : ''}
            </div>
          `;
        }

        htmlContent.innerHTML = linkBar + `<pre style="font-family:monospace;font-size:13px;white-space:pre-wrap;word-break:break-all">${escapeHtml(raw)}</pre>`;
      } else {
        htmlContent.innerHTML = `<div style="color:#c5221f;padding:20px">Preview error: ${escapeHtml(data.error || 'Unable to load file preview.')}</div>`;
      }
    })
    .catch(err => {
      loading.style.display = 'none';
      htmlContent.style.display = 'block';
      htmlContent.innerHTML = `<div style="color:#c5221f;padding:20px">Preview failed: ${escapeHtml(err.message)}</div>`;
    });
}

function closePreviewLightbox() {
  document.getElementById('previewLightbox').style.display = 'none';
}



function triggerFileUpload() {
  document.getElementById('realFileInput').click();
}

function handleFileSelected(event) {
  const file = event.target.files[0];
  if (!file) return;
  uploadFileObject(file);
}

function uploadFileObject(file) {
  showUploadPopup(file.name);

  const formData = new FormData();
  formData.append('file', file);

  fetch('/api/drive/upload', {
    method: 'POST',
    body: formData
  })
    .then(r => {
      if (r.status === 401) {
        showToast('⚠ Session expired. Redirecting to login...');
        setTimeout(() => { window.location.href = '/login'; }, 1000);
        return null;
      }
      return r.json();
    })
    .then(data => {
      if (!data) return;
      if (data.success) {
        showToast(`✓ "${file.name}" uploaded successfully!`);
        updateUploadPopupSuccess(file.name);
        loadFiles();
      } else {
        showToast('⚠ ' + (data.error || 'Upload failed'));
        closeUploadPopup();
      }
    })
    .catch(err => {
      showToast('⚠ Upload failed: ' + err.message);
      closeUploadPopup();
    })
    .finally(() => {
      document.getElementById('realFileInput').value = '';
    });
}

function showUploadPopup(filename) {
  const popup = document.getElementById('uploadPopup');
  const body = document.getElementById('upBody');
  const title = document.getElementById('upTitle');

  title.textContent = 'Uploading...';
  body.innerHTML = `
    <div class="up-item">
      <span class="up-item-name">${escapeHtml(filename)}</span>
      <span style="font-size:12px;color:#1a73e8">Uploading...</span>
    </div>
  `;
  popup.style.display = 'block';
}

function updateUploadPopupSuccess(filename) {
  const body = document.getElementById('upBody');
  const title = document.getElementById('upTitle');

  title.textContent = '1 upload complete';
  body.innerHTML = `
    <div class="up-item">
      <span class="up-item-name">${escapeHtml(filename)}</span>
      <span class="up-item-check">✓</span>
    </div>
  `;
  setTimeout(() => closeUploadPopup(), 4000);
}

function closeUploadPopup() {
  document.getElementById('uploadPopup').style.display = 'none';
}

function setupDragAndDrop() {
  const dropZone = document.getElementById('dropZone');
  if (!dropZone) return;

  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => e.preventDefault(), false);
  });

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.style.background = '#f0f6ff', false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, () => dropZone.style.background = '', false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      uploadFileObject(files[0]);
    }
  });
}

function toggleUserMenu() {
  document.getElementById('userDropdown').classList.toggle('show');
}

function setupGlobalEvents() {
  window.addEventListener('click', (e) => {
    if (!e.target.closest('.user-avatar-btn') && !e.target.closest('.user-dropdown')) {
      const ud = document.getElementById('userDropdown');
      if (ud) ud.classList.remove('show');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closePreviewLightbox();
    }
  });
}

function showToast(msg) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3500);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
