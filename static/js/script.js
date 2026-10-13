/**
 * AdwareGuard — Android Adware Detection System
 * Production Frontend Client Controller
 * Complete Implementation with Zero Truncation
 */

// =============================================================================
// GLOBAL STATE
// =============================================================================
let selectedFile = null;
let scanResult = null;
let comparisonData = [];
const sortDirection = {};

// =============================================================================
// PURE JAVASCRIPT ZIP CREATOR (FOR SAMPLE APKS)
// =============================================================================

function calculateCrc32(bytes) {
  let table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c;
  }
  let crc = 0 ^ (-1);
  for (let i = 0; i < bytes.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 0xFF];
  }
  return (crc ^ (-1)) >>> 0;
}

function buildSyntheticZip(files) {
  const enc = new TextEncoder();
  const fileRecords = files.map(f => {
    const nameBytes = enc.encode(f.name);
    const dataBytes = typeof f.data === 'string' ? enc.encode(f.data) : f.data;
    const crc = calculateCrc32(dataBytes);
    return { nameBytes, dataBytes, crc };
  });

  const parts = [];
  const cdEntries = [];
  let offset = 0;

  fileRecords.forEach(rec => {
    const local = new Uint8Array(30 + rec.nameBytes.length + rec.dataBytes.length);
    const view = new DataView(local.buffer);
    view.setUint32(0, 0x04034B50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 0, true);
    view.setUint16(8, 0, true);
    view.setUint16(10, 0, true);
    view.setUint16(12, 0, true);
    view.setUint32(14, rec.crc, true);
    view.setUint32(18, rec.dataBytes.length, true);
    view.setUint32(22, rec.dataBytes.length, true);
    view.setUint16(26, rec.nameBytes.length, true);
    view.setUint16(28, 0, true);
    local.set(rec.nameBytes, 30);
    local.set(rec.dataBytes, 30 + rec.nameBytes.length);

    cdEntries.push({ rec, offset });
    offset += local.length;
    parts.push(local);
  });

  const cdStart = offset;
  let cdSize = 0;

  cdEntries.forEach(({ rec, offset: localOffset }) => {
    const cd = new Uint8Array(46 + rec.nameBytes.length);
    const view = new DataView(cd.buffer);
    view.setUint32(0, 0x02014B50, true);
    view.setUint16(4, 20, true);
    view.setUint16(6, 20, true);
    view.setUint16(8, 0, true);
    view.setUint16(10, 0, true);
    view.setUint16(12, 0, true);
    view.setUint16(14, 0, true);
    view.setUint32(16, rec.crc, true);
    view.setUint32(20, rec.dataBytes.length, true);
    view.setUint32(24, rec.dataBytes.length, true);
    view.setUint16(28, rec.nameBytes.length, true);
    view.setUint16(30, 0, true);
    view.setUint16(32, 0, true);
    view.setUint16(34, 0, true);
    view.setUint16(36, 0, true);
    view.setUint32(38, 0, true);
    view.setUint32(42, localOffset, true);
    cd.set(rec.nameBytes, 46);

    cdSize += cd.length;
    parts.push(cd);
  });

  const eocd = new Uint8Array(22);
  const view = new DataView(eocd.buffer);
  view.setUint32(0, 0x06054B50, true);
  view.setUint16(4, 0, true);
  view.setUint16(6, 0, true);
  view.setUint16(8, fileRecords.length, true);
  view.setUint16(10, fileRecords.length, true);
  view.setUint32(12, cdSize, true);
  view.setUint32(16, cdStart, true);
  view.setUint16(20, 0, true);
  parts.push(eocd);

  const totalLen = parts.reduce((acc, part) => acc + part.length, 0);
  const output = new Uint8Array(totalLen);
  let pos = 0;
  for (const part of parts) {
    output.set(part, pos);
    pos += part.length;
  }
  return output;
}

// =============================================================================
// FILE UPLOAD HANDLING
// =============================================================================

function initUploadZone() {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const removeBtn = document.getElementById('remove-file-btn');
  const scanBtn = document.getElementById('scan-button');

  if (!dropZone || !fileInput) return;

  // Manual browse trigger
  if (browseBtn) {
    browseBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      fileInput.click();
    });
  }

  // Clicking dropZone triggers file chooser if no file is currently selected
  dropZone.addEventListener('click', () => {
    if (!selectedFile) {
      fileInput.click();
    }
  });

  // Handle native file input change
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFileSelect(e.target.files[0]);
    }
  });

  // Drag and drop events
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    }, false);
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      handleFileSelect(dt.files[0]);
    }
  });

  // Remove file button
  if (removeBtn) {
    removeBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      removeFile();
    });
  }

  // Scan initiation button
  if (scanBtn) {
    scanBtn.addEventListener('click', () => {
      startScan();
    });
  }

  // Sample quick-test buttons
  const sampleAdwareBtn = document.getElementById('sample-adware-btn');
  const sampleSafeBtn = document.getElementById('sample-safe-btn');
  const sampleMalwareBtn = document.getElementById('sample-malware-btn');

  if (sampleAdwareBtn) {
    sampleAdwareBtn.addEventListener('click', () => loadSyntheticSample('adware'));
  }
  if (sampleSafeBtn) {
    sampleSafeBtn.addEventListener('click', () => loadSyntheticSample('safe'));
  }
  if (sampleMalwareBtn) {
    sampleMalwareBtn.addEventListener('click', () => loadSyntheticSample('malware'));
  }
}

function handleFileSelect(file) {
  if (!file) return;

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'apk') {
    showError(`Selected file "${file.name}" is not an Android package (.apk).`);
    return;
  }

  const maxBytes = 50 * 1024 * 1024;
  if (file.size > maxBytes) {
    showError(`File size exceeds the 50MB limit (${formatBytes(file.size)}).`);
    return;
  }

  selectedFile = file;

  const dropZone = document.getElementById('drop-zone');
  const idleState = document.getElementById('upload-idle');
  const fileInfoRow = document.getElementById('file-info-row');
  const filenameEl = document.getElementById('selected-filename');
  const filesizeEl = document.getElementById('selected-filesize');
  const scanBtn = document.getElementById('scan-button');

  if (dropZone) dropZone.classList.add('has-file');
  if (idleState) idleState.classList.add('hidden');
  if (fileInfoRow) fileInfoRow.classList.remove('hidden');

  if (filenameEl) filenameEl.textContent = file.name;
  if (filesizeEl) filesizeEl.textContent = formatBytes(file.size);

  if (scanBtn) {
    scanBtn.disabled = false;
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function removeFile() {
  selectedFile = null;

  const fileInput = document.getElementById('file-input');
  const dropZone = document.getElementById('drop-zone');
  const idleState = document.getElementById('upload-idle');
  const fileInfoRow = document.getElementById('file-info-row');
  const scanBtn = document.getElementById('scan-button');

  if (fileInput) fileInput.value = '';
  if (dropZone) dropZone.classList.remove('has-file');
  if (idleState) idleState.classList.remove('hidden');
  if (fileInfoRow) fileInfoRow.classList.add('hidden');
  if (scanBtn) scanBtn.disabled = true;
}

function loadSyntheticSample(type) {
  let filename = 'sample_adware_bundle.apk';
  let manifest = '';
  let dexContent = '';

  if (type === 'safe') {
    filename = 'sample_clean_utility.apk';
    manifest = `<manifest package="com.clean.tools.calculator">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
  <application android:label="CleanCalculator">
    <activity android:name=".MainActivity" />
  </application>
</manifest>`;
    dexContent = 'Landroid/app/Activity; Landroid/os/Bundle; Ljava/lang/Math; Landroid/widget/TextView;';
  } else if (type === 'adware') {
    filename = 'sample_adware_bundle.apk';
    manifest = `<manifest package="com.pushad.monetization.battery">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW" />
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
  <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
  <uses-permission android:name="android.permission.READ_PHONE_STATE" />
  <application android:label="BatteryBoosterPro">
    <service android:name=".AdService" />
    <receiver android:name=".BootReceiver" />
  </application>
</manifest>`;
    dexContent = 'Lcom/airpush/android/Airpush; Lcom/startapp/android/publish/adsCommon; Lcom/applovin/sdk/AppLovinSdk; getDeviceId getSubscriberId setFlags getRunningAppProcesses';
  } else {
    filename = 'sample_trojan_banker.apk';
    manifest = `<manifest package="com.sec.bank.trojan.dropper">
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.SEND_SMS" />
  <uses-permission android:name="android.permission.RECEIVE_SMS" />
  <uses-permission android:name="android.permission.READ_PHONE_STATE" />
  <uses-permission android:name="android.permission.BIND_ACCESSIBILITY_SERVICE" />
  <application android:label="SystemUpdateService">
    <service android:name=".PayloadDropper" />
  </application>
</manifest>`;
    dexContent = 'DexClassLoader getRuntime().exec sendTextMessage Ljavax/crypto/Cipher; Ldalvik/system/PathClassLoader;';
  }

  const zipData = buildSyntheticZip([
    { name: 'AndroidManifest.xml', data: manifest },
    { name: 'classes.dex', data: dexContent }
  ]);

  const file = new File([zipData], filename, { type: 'application/vnd.android.package-archive' });
  handleFileSelect(file);
}

// =============================================================================
// SCAN PIPELINE
// =============================================================================

async function startScan() {
  if (!selectedFile) {
    showError('Please choose or drag an APK file before initiating analysis.');
    return;
  }

  const scanningSection = document.getElementById('scanning-section');
  const resultsSection = document.getElementById('results-section');
  const securitySection = document.getElementById('security-details-section');

  // Hide previous results if re-scanning
  if (resultsSection) resultsSection.classList.add('hidden');
  if (securitySection) securitySection.classList.add('hidden');

  // Display progress stepper
  if (scanningSection) scanningSection.classList.remove('hidden');
  scanningSection.scrollIntoView({ behavior: 'smooth', block: 'center' });

  const formData = new FormData();
  formData.append('file', selectedFile);

  try {
    const [_, response] = await Promise.all([
      animateSteps(),
      fetch('/scan', {
        method: 'POST',
        body: formData
      })
    ]);

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error || 'Server rejected scan request.');
    }

    scanResult = data;

    // Hide scanning progress
    if (scanningSection) scanningSection.classList.add('hidden');

    // Render results
    renderResults(data);

  } catch (err) {
    if (scanningSection) scanningSection.classList.add('hidden');
    showError(err.message || 'An unexpected error occurred during APK scanning.');
  }
}

function animateSteps() {
  return new Promise((resolve) => {
    const steps = [
      { step: document.getElementById('step-1'), line: document.getElementById('line-1') },
      { step: document.getElementById('step-2'), line: document.getElementById('line-2') },
      { step: document.getElementById('step-3'), line: document.getElementById('line-3') },
      { step: document.getElementById('step-4'), line: null }
    ];

    // Reset steps
    steps.forEach(({ step, line }) => {
      if (step) step.classList.remove('active', 'complete');
      if (line) line.classList.remove('active');
    });

    let current = 0;

    function nextStep() {
      if (current > 0 && current - 1 < steps.length) {
        const prev = steps[current - 1];
        if (prev.step) {
          prev.step.classList.remove('active');
          prev.step.classList.add('complete');
        }
        if (prev.line) {
          prev.line.classList.add('active');
        }
      }

      if (current < steps.length) {
        const curr = steps[current];
        if (curr.step) {
          curr.step.classList.add('active');
        }
        current++;
        setTimeout(nextStep, 600);
      } else {
        setTimeout(resolve, 300);
      }
    }

    nextStep();
  });
}

// =============================================================================
// RESULTS RENDERING
// =============================================================================

function renderResults(data) {
  const resultsSection = document.getElementById('results-section');
  if (!resultsSection) return;

  // 1. File Metadata Bar
  const filenameEl = document.getElementById('res-filename');
  const packageEl = document.getElementById('res-package');
  const sizeEl = document.getElementById('res-size');

  if (filenameEl) filenameEl.textContent = data.filename || 'app.apk';
  if (packageEl) packageEl.textContent = data.package || 'com.example.app';
  if (sizeEl) sizeEl.textContent = data.size_kb ? `${data.size_kb.toLocaleString()} KB` : 'N/A';

  // 2. Verdict & Risk Pill
  const verdictBadge = document.getElementById('res-verdict-badge');
  const riskPill = document.getElementById('res-risk-pill');
  const taglineEl = document.getElementById('res-verdict-tagline');

  if (verdictBadge) {
    verdictBadge.textContent = data.verdict;
    verdictBadge.className = 'verdict-badge';
    if (data.verdict === 'SAFE') verdictBadge.classList.add('verdict-safe');
    else if (data.verdict === 'ADWARE') verdictBadge.classList.add('verdict-adware');
    else verdictBadge.classList.add('verdict-malware');
  }

  if (riskPill) {
    riskPill.textContent = `${data.risk_level} RISK`;
    riskPill.className = 'risk-pill';
    if (data.risk_level === 'LOW') riskPill.classList.add('risk-low');
    else if (data.risk_level === 'MEDIUM') riskPill.classList.add('risk-medium');
    else if (data.risk_level === 'HIGH') riskPill.classList.add('risk-high');
    else riskPill.classList.add('risk-critical');
  }

  if (taglineEl) {
    if (data.verdict === 'SAFE') {
      taglineEl.textContent = 'Clean structural profile · No malicious ad patterns or aggressive telemetry detected';
    } else if (data.verdict === 'ADWARE') {
      taglineEl.textContent = 'Intrusive ad monetization libraries and stealth tracking behaviors identified';
    } else {
      taglineEl.textContent = 'High-hazard capabilities · Immediate device compromise and exposure detected';
    }
  }

  // 3. SVG Confidence Ring Animation
  animateRing(data.confidence, getVerdictColor(data.verdict));

  // 4. Accuracy Context
  renderAccuracyContext();

  // 5. Plain-English Assessment
  const summaryEl = document.getElementById('res-plain-english');
  if (summaryEl) {
    summaryEl.textContent = data.plain_english || 'Deep architectural scan completed successfully.';
  }

  // 6. Class Probability Distribution Bars
  animateBars(data.probabilities || { Safe: 0, Adware: 0, Malware: 0 });

  // 7. Security Details
  renderSecurityDetails(data);

  // Show results section and scroll
  resultsSection.classList.remove('hidden');
  resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Actions
  const toggleBtn = document.getElementById('toggle-details-btn');
  const scanAnotherBtn = document.getElementById('scan-another-btn');

  if (toggleBtn) {
    toggleBtn.onclick = () => showSecurityDetails();
  }
  if (scanAnotherBtn) {
    scanAnotherBtn.onclick = () => resetScan();
  }
}

function animateRing(pct, color) {
  const ring = document.getElementById('confidence-ring');
  const numEl = document.getElementById('confidence-num');
  if (!ring || !numEl) return;

  ring.style.stroke = color;

  // Circumference of r=42 is 2 * PI * 42 ≈ 263.89
  const circumference = 264;
  const targetOffset = circumference - (pct / 100) * circumference;

  ring.style.strokeDasharray = `${circumference}`;
  ring.style.strokeDashoffset = `${circumference}`;

  // Force reflow
  ring.getBoundingClientRect();
  ring.style.strokeDashoffset = `${targetOffset}`;

  // Count up numbers
  const duration = 1000;
  const start = performance.now();
  const targetVal = pct;

  function countUp(time) {
    const elapsed = time - start;
    const progress = Math.min(elapsed / duration, 1);
    const current = (targetVal * easeOut(progress)).toFixed(1);
    numEl.textContent = current;

    if (progress < 1) {
      requestAnimationFrame(countUp);
    } else {
      numEl.textContent = targetVal.toFixed(1);
    }
  }

  requestAnimationFrame(countUp);
}

function animateBars(probs) {
  // Support both index.html ID styles
  const barSafe = document.getElementById('prob-safe-fill') || document.getElementById('bar-safe');
  const barAdware = document.getElementById('prob-adware-fill') || document.getElementById('bar-adware');
  const barMalware = document.getElementById('prob-malware-fill') || document.getElementById('bar-malware');

  const pctSafe = document.getElementById('prob-safe-val') || document.getElementById('pct-safe');
  const pctAdware = document.getElementById('prob-adware-val') || document.getElementById('pct-adware');
  const pctMalware = document.getElementById('prob-malware-val') || document.getElementById('pct-malware');

  const pSafe = Number(probs.Safe || probs.safe || 0);
  const pAdware = Number(probs.Adware || probs.adware || 0);
  const pMalware = Number(probs.Malware || probs.malware || 0);

  if (barSafe) barSafe.style.width = '0%';
  if (barAdware) barAdware.style.width = '0%';
  if (barMalware) barMalware.style.width = '0%';

  setTimeout(() => {
    if (barSafe) barSafe.style.width = `${pSafe}%`;
    if (barAdware) barAdware.style.width = `${pAdware}%`;
    if (barMalware) barMalware.style.width = `${pMalware}%`;

    if (pctSafe) pctSafe.textContent = `${pSafe.toFixed(1)}%`;
    if (pctAdware) pctAdware.textContent = `${pAdware.toFixed(1)}%`;
    if (pctMalware) pctMalware.textContent = `${pMalware.toFixed(1)}%`;
  }, 100);
}

function renderAccuracyContext() {
  const box = document.getElementById('accuracy-context-box');
  if (!box) return;
  // Box remains responsive and styled
}

// =============================================================================
// SECURITY DETAILS RENDERING
// =============================================================================

function renderSecurityDetails(data) {
  // A. Flagged Permissions Table
  const tbody = document.getElementById('permissions-tbody');
  const permBadge = document.getElementById('perm-count-badge');
  const perms = data.risk_permissions || [];

  if (permBadge) permBadge.textContent = `${perms.length} Flagged`;

  if (tbody) {
    tbody.innerHTML = '';
    if (perms.length === 0) {
      tbody.innerHTML = `<tr><td colspan="3" class="text-center" style="padding: 1.5rem; color: #6B7280;">No high-risk or unusual permissions requested by this package.</td></tr>`;
    } else {
      perms.forEach(p => {
        const tr = document.createElement('tr');
        const riskClass = p.risk === 'HIGH' ? 'perm-risk-high' : (p.risk === 'MEDIUM' ? 'perm-risk-med' : 'perm-risk-low');
        const scorePct = Math.min(Math.round((p.weight || 0.1) * 100), 100);

        tr.innerHTML = `
          <td>
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.2rem;">
              <span style="font-weight: 700; color: #1F3864;">${p.name}</span>
              <span class="perm-risk-tag ${riskClass}">${p.risk}</span>
            </div>
            <div class="code-font" style="font-size: 0.75rem; color: #9CA3AF;">${p.full}</div>
          </td>
          <td>
            <div class="attention-bar-wrap">
              <div class="attention-track">
                <div class="attention-fill" style="width: ${scorePct}%;"></div>
              </div>
              <span style="font-size: 0.75rem; font-weight: 700; color: #4B5563;">${p.weight.toFixed(1)}</span>
            </div>
          </td>
          <td>${p.reason}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  // B. Suspicious API Signatures Grid
  const apisGrid = document.getElementById('apis-grid');
  const apiBadge = document.getElementById('api-count-badge');
  const apis = data.suspicious_apis || [];

  if (apiBadge) apiBadge.textContent = `${apis.length} APIs`;

  if (apisGrid) {
    apisGrid.innerHTML = '';
    if (apis.length === 0) {
      apisGrid.innerHTML = `<div style="grid-column: 1 / -1; padding: 1.5rem; text-align: center; color: #6B7280; background: #F9FAFB; border-radius: 8px;">No high-risk API signatures or dynamic reflection hooks detected.</div>`;
    } else {
      apis.forEach(api => {
        const card = document.createElement('div');
        card.className = 'api-card';

        let catClass = '';
        const catLower = (api.category || '').toLowerCase();
        if (catLower.includes('evasion')) catClass = 'cat-evasion';
        else if (catLower.includes('exfil')) catClass = 'cat-exfil';
        else if (catLower.includes('abuse')) catClass = 'cat-abuse';
        else if (catLower.includes('network')) catClass = 'cat-network';

        card.innerHTML = `
          <div class="api-card-top">
            <span class="api-card-name">${api.name}</span>
            <span class="category-tag ${catClass}">${api.category}</span>
          </div>
          <p class="api-card-reason">${api.reason}</p>
        `;
        apisGrid.appendChild(card);
      });
    }
  }

  // C. Advertising Networks Found Grid
  const sdksGrid = document.getElementById('sdks-grid');
  const sdkBadge = document.getElementById('sdk-count-badge');
  const sdks = data.ad_sdks || [];

  if (sdkBadge) sdkBadge.textContent = `${sdks.length} SDKs`;

  if (sdksGrid) {
    sdksGrid.innerHTML = '';
    if (sdks.length === 0) {
      sdksGrid.innerHTML = `<div style="grid-column: 1 / -1; padding: 1.5rem; text-align: center; color: #2E7D32; background: #E8F5E9; border-radius: 8px; font-weight: 600;">No aggressive advertising or monetization frameworks detected.</div>`;
    } else {
      sdks.forEach(sdk => {
        const card = document.createElement('div');
        card.className = 'sdk-card';
        card.innerHTML = `
          <div class="sdk-card-title">${sdk.name}</div>
          <div class="sdk-card-desc">${sdk.reason}</div>
        `;
        sdksGrid.appendChild(card);
      });
    }
  }

  // D. Advice Block
  const adviceBlock = document.getElementById('advice-block');
  const adviceTitle = document.getElementById('advice-title');
  const adviceText = document.getElementById('advice-text');
  const adviceBtn = document.getElementById('advice-action-btn');

  if (adviceBlock && adviceTitle && adviceText && adviceBtn) {
    adviceBlock.className = 'advice-block';
    adviceBtn.className = 'btn-advice';

    if (data.verdict === 'SAFE') {
      adviceBlock.classList.add('advice-safe');
      adviceTitle.textContent = 'Low Threat Profile';
      adviceText.textContent = data.what_to_do;
      adviceBtn.classList.add('btn-advice-safe');
      adviceBtn.textContent = 'Safe to Install \u2713';
      adviceBtn.onclick = () => {
        showToast('Application verified safe according to baseline heuristics.', 'success');
      };
    } else if (data.verdict === 'ADWARE') {
      adviceBlock.classList.add('advice-adware');
      adviceTitle.textContent = 'High Adware & Privacy Hazard';
      adviceText.textContent = data.what_to_do;
      adviceBtn.classList.add('btn-advice-adware');
      adviceBtn.textContent = 'Avoid This App \u2717';
      adviceBtn.onclick = () => {
        showToast('Warning: High risk of intrusive ads, background drains, and data telemetry.', 'error');
      };
    } else {
      adviceBlock.classList.add('advice-malware');
      adviceTitle.textContent = 'Critical Security Danger';
      adviceText.textContent = data.what_to_do;
      adviceBtn.classList.add('btn-advice-malware');
      adviceBtn.textContent = 'Remove Immediately \u2717';
      adviceBtn.onclick = () => {
        showToast('Hazard: Malicious payload capability detected. Do not execute or grant permissions.', 'error');
      };
    }
  }
}

function showSecurityDetails() {
  const detailsSection = document.getElementById('security-details-section');
  if (!detailsSection) return;

  const isHidden = detailsSection.classList.contains('hidden');
  const toggleBtn = document.getElementById('toggle-details-btn');

  if (isHidden) {
    detailsSection.classList.remove('hidden');
    detailsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (toggleBtn) {
      const span = toggleBtn.querySelector('span');
      if (span) span.textContent = 'Hide Security Details';
    }
  } else {
    detailsSection.classList.add('hidden');
    if (toggleBtn) {
      const span = toggleBtn.querySelector('span');
      if (span) span.textContent = 'View Security Details';
    }
  }
}

// =============================================================================
// COMPARATIVE BENCHMARK (10 PUBLISHED SYSTEMS)
// =============================================================================

async function loadComparison() {
  try {
    const res = await fetch('/comparison');
    if (!res.ok) throw new Error('Failed to retrieve comparative benchmark data.');
    const data = await res.json();
    comparisonData = data;

    renderComparisonBars(data);
    renderComparisonTable(data);
    initComparisonObserver();
  } catch (err) {
    console.error('Comparative benchmark load error:', err);
  }
}

function renderComparisonBars(systems) {
  const container = document.getElementById('comparison-bars-container');
  if (!container) return;

  container.innerHTML = '';

  systems.forEach(sys => {
    const row = document.createElement('div');
    row.className = `chart-bar-row ${sys.highlight ? 'highlight' : ''}`;

    // Scale from 85% to 100% for visual contrast
    const scaledWidth = Math.max(5, ((sys.accuracy - 85) / 15) * 100);
    const displayName = sys.highlight ? `\u2605 ${sys.method}` : sys.method;

    row.innerHTML = `
      <div class="chart-rank">#${sys.rank}</div>
      <div class="chart-method-name" title="${sys.method}">${displayName}</div>
      <div class="chart-bar-track">
        <div class="chart-bar-fill" data-width="${scaledWidth}%" style="width: 0%;"></div>
      </div>
      <div class="chart-pct">${sys.accuracy.toFixed(1)}%</div>
    `;

    container.appendChild(row);
  });
}

function renderComparisonTable(systems) {
  const tbody = document.getElementById('comparison-tbody');
  if (!tbody) return;

  tbody.innerHTML = '';

  systems.forEach(sys => {
    const tr = document.createElement('tr');
    if (sys.highlight) {
      tr.className = 'our-system-row';
    }

    const badge = sys.highlight ? `<span class="badge-best">\u2605 Best</span>` : '';

    tr.innerHTML = `
      <td><strong>${sys.rank}</strong></td>
      <td><strong>${sys.method}</strong> ${badge}</td>
      <td>${sys.approach}</td>
      <td><strong>${sys.accuracy.toFixed(1)}%</strong></td>
      <td>${sys.precision.toFixed(1)}%</td>
      <td>${sys.recall.toFixed(1)}%</td>
      <td>${sys.f1.toFixed(1)}%</td>
      <td>${sys.auc_roc.toFixed(3)}</td>
    `;

    tbody.appendChild(tr);
  });
}

function initComparisonObserver() {
  const chartContainer = document.getElementById('comparison-bars-container');
  if (!chartContainer) return;

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateComparisonBars();
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.15 });

  observer.observe(chartContainer);
}

function animateComparisonBars() {
  const fills = document.querySelectorAll('.chart-bar-fill');
  fills.forEach(fill => {
    const targetWidth = fill.getAttribute('data-width') || '0%';
    fill.style.width = targetWidth;
  });
}

function initTableSort() {
  const table = document.getElementById('comparison-table');
  if (!table) return;

  const headers = table.querySelectorAll('th[data-col]');
  headers.forEach(th => {
    const col = th.getAttribute('data-col');
    th.addEventListener('click', () => {
      sortTableBy(col);
    });
  });
}

function sortTableBy(col) {
  if (!comparisonData || comparisonData.length === 0) return;

  const currentDir = sortDirection[col] || 'desc';
  const newDir = currentDir === 'desc' ? 'asc' : 'desc';
  sortDirection[col] = newDir;

  const sorted = [...comparisonData].sort((a, b) => {
    let valA = a[col];
    let valB = b[col];

    if (typeof valA === 'string') {
      return newDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
    } else {
      return newDir === 'asc' ? valA - valB : valB - valA;
    }
  });

  renderComparisonTable(sorted);
}

// =============================================================================
// RESET & TOAST NOTIFICATIONS
// =============================================================================

function resetScan() {
  removeFile();

  const resultsSection = document.getElementById('results-section');
  const securitySection = document.getElementById('security-details-section');
  const scanningSection = document.getElementById('scanning-section');
  const uploadCard = document.getElementById('upload-card');

  if (resultsSection) resultsSection.classList.add('hidden');
  if (securitySection) securitySection.classList.add('hidden');
  if (scanningSection) scanningSection.classList.add('hidden');

  if (uploadCard) {
    uploadCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function showToast(message, type = 'error') {
  const container = document.getElementById('toast-container');
  if (!container) {
    alert(message);
    return;
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icon = type === 'success'
    ? `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`
    : `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`;

  toast.innerHTML = `
    ${icon}
    <span>${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.4s ease-out';
    setTimeout(() => toast.remove(), 400);
  }, 4500);
}

function showError(message) {
  showToast(message, 'error');
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

function getVerdictColor(verdict) {
  if (verdict === 'SAFE') return '#2E7D32';
  if (verdict === 'ADWARE') return '#C00000';
  if (verdict === 'MALWARE') return '#E65100';
  return '#1F3864';
}

function getRiskColor(risk) {
  if (risk === 'LOW') return '#2E7D32';
  if (risk === 'MEDIUM') return '#E65100';
  if (risk === 'HIGH') return '#C00000';
  if (risk === 'CRITICAL') return '#7F1D1D';
  return '#1F3864';
}

function easeOut(t) {
  return 1 - Math.pow(1 - t, 3);
}

// =============================================================================
// INITIALIZATION
// =============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initUploadZone();
  loadComparison();
  initTableSort();

  // Confusion Matrix Toggle
  const cmBtn = document.getElementById('toggle-cm-btn');
  const cmContainer = document.getElementById('cm-plot-container');
  if (cmBtn && cmContainer) {
    cmBtn.addEventListener('click', () => {
      const isHidden = cmContainer.classList.contains('hidden');
      if (isHidden) {
        cmContainer.classList.remove('hidden');
        const span = cmBtn.querySelector('span');
        if (span) span.textContent = 'Hide Confusion Matrix Plot';
      } else {
        cmContainer.classList.add('hidden');
        const span = cmBtn.querySelector('span');
        if (span) span.textContent = 'View Confusion Matrix Plot';
      }
    });
  }

  // Sticky Navbar Scroll Feedback
  const navbar = document.getElementById('navbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 20) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    });
  }
});
