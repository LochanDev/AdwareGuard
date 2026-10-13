/**
 * AdwareGuard Frontend Controller
 * ===============================
 * Handles file drag-and-drop, sequential stepper animation,
 * asynchronous inference API calls, SVG circular ring animation,
 * dynamic risk attribution rendering, and dark mode toggling.
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('apk-file-input');
  const browseBtn = document.getElementById('browse-btn');
  const fileBanner = document.getElementById('selected-file-banner');
  const filenameText = document.getElementById('selected-filename');
  const filesizeText = document.getElementById('selected-filesize');
  const clearFileBtn = document.getElementById('clear-file-btn');
  const scanSubmitBtn = document.getElementById('scan-submit-btn');
  const errorAlert = document.getElementById('error-alert');
  const errorMessage = document.getElementById('error-message');
  const retryBtn = document.getElementById('retry-btn');

  // Sample Buttons
  const sampleAdwareBtn = document.getElementById('sample-adware-btn');
  const sampleBenignBtn = document.getElementById('sample-benign-btn');
  const sampleMalwareBtn = document.getElementById('sample-malware-btn');

  // Animation & Results Containers
  const uploadCard = document.getElementById('upload-card');
  const scanningCard = document.getElementById('scanning-card');
  const resultsCard = document.getElementById('results-card');
  const explainabilityCard = document.getElementById('explainability-section');
  const toggleExplainBtn = document.getElementById('toggle-explainability-btn');
  const scanAnotherBtn = document.getElementById('scan-another-btn');

  // Stepper Elements
  const steps = [
    document.getElementById('step-1'),
    document.getElementById('step-2'),
    document.getElementById('step-3'),
    document.getElementById('step-4')
  ];

  // Dark Mode Elements
  const themeToggleBtn = document.getElementById('theme-toggle-btn');
  const themeMoonIcon = document.getElementById('theme-moon-icon');
  const themeSunIcon = document.getElementById('theme-sun-icon');

  let currentFile = null;
  let activeSampleType = null;

  // =================================================================
  // 1. THEME INITIALIZATION & TOGGLING (DARK MODE)
  // =================================================================
  function initTheme() {
    const savedTheme = localStorage.getItem('adwareguard_theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
      setDarkMode(true);
    } else {
      setDarkMode(false);
    }
  }

  function setDarkMode(isDark) {
    if (isDark) {
      document.body.classList.add('dark-mode');
      themeMoonIcon.classList.add('hidden');
      themeSunIcon.classList.remove('hidden');
      localStorage.setItem('adwareguard_theme', 'dark');
    } else {
      document.body.classList.remove('dark-mode');
      themeMoonIcon.classList.remove('hidden');
      themeSunIcon.classList.add('hidden');
      localStorage.setItem('adwareguard_theme', 'light');
    }
  }

  themeToggleBtn.addEventListener('click', () => {
    const isDark = document.body.classList.contains('dark-mode');
    setDarkMode(!isDark);
  });

  initTheme();

  // =================================================================
  // 2. DRAG & DROP AND FILE SELECTION
  // =================================================================
  browseBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fileInput.click();
  });

  dropZone.addEventListener('click', () => {
    fileInput.click();
  });

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileSelected(files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    hideError();
    activeSampleType = null;

    // Validate extension
    const nameLower = file.name.toLowerCase();
    if (!nameLower.endsWith('.apk')) {
      showError('Selected file is not an Android APK package. Please choose a .apk file.');
      return;
    }

    // Validate size (max 250MB)
    const maxSizeBytes = 250 * 1024 * 1024;
    if (file.size > maxSizeBytes) {
      showError('File exceeds maximum upload size limit (250 MB). Please choose a smaller APK.');
      return;
    }

    currentFile = file;
    filenameText.textContent = file.name;
    const sizeKB = Math.round(file.size / 1024);
    filesizeText.textContent = `${sizeKB.toLocaleString()} KB`;

    fileBanner.classList.remove('hidden');
    scanSubmitBtn.removeAttribute('disabled');
  }

  clearFileBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    resetFileInput();
  });

  function resetFileInput() {
    currentFile = null;
    activeSampleType = null;
    fileInput.value = '';
    fileBanner.classList.add('hidden');
    scanSubmitBtn.setAttribute('disabled', 'true');
    hideError();
  }

  // =================================================================
  // 3. SAMPLE BENCHMARK BUTTON HANDLERS
  // =================================================================
  sampleAdwareBtn.addEventListener('click', () => triggerSampleRun('adware', 'Sample Adware APK (Flashlight Adware)'));
  sampleBenignBtn.addEventListener('click', () => triggerSampleRun('benign', 'Sample Benign APK (Calculator Utility)'));
  sampleMalwareBtn.addEventListener('click', () => triggerSampleRun('malware', 'Sample Malware APK (Banking Dropper)'));

  function triggerSampleRun(type, label) {
    hideError();
    currentFile = null;
    activeSampleType = type;
    fileInput.value = '';

    filenameText.textContent = label;
    filesizeText.textContent = 'Benchmark Profile';
    fileBanner.classList.remove('hidden');
    scanSubmitBtn.removeAttribute('disabled');

    // Auto-initiate scan for immediate test feedback
    startScanPipeline();
  }

  // =================================================================
  // 4. SCAN EXECUTION & STEPPER ANIMATION
  // =================================================================
  scanSubmitBtn.addEventListener('click', () => {
    startScanPipeline();
  });

  function startScanPipeline() {
    if (!currentFile && !activeSampleType) {
      showError('Please select an APK file or choose a benchmark profile to scan.');
      return;
    }

    hideError();
    uploadCard.classList.add('hidden');
    resultsCard.classList.add('hidden');
    explainabilityCard.classList.add('hidden');
    scanningCard.classList.remove('hidden');

    // Reset and step through the 4-phase stepper
    resetStepper();
    animateStepper(() => {
      // Stepper completed, execute POST request
      executeScanRequest();
    });
  }

  function resetStepper() {
    steps.forEach(step => {
      step.classList.remove('active', 'completed');
    });
  }

  function animateStepper(callback) {
    const stepDuration = 700; // ms per step

    steps[0].classList.add('active');

    setTimeout(() => {
      steps[0].classList.remove('active');
      steps[0].classList.add('completed');
      steps[1].classList.add('active');
    }, stepDuration);

    setTimeout(() => {
      steps[1].classList.remove('active');
      steps[1].classList.add('completed');
      steps[2].classList.add('active');
    }, stepDuration * 2);

    setTimeout(() => {
      steps[2].classList.remove('active');
      steps[2].classList.add('completed');
      steps[3].classList.add('active');
    }, stepDuration * 3);

    setTimeout(() => {
      steps[3].classList.remove('active');
      steps[3].classList.add('completed');
      if (typeof callback === 'function') {
        callback();
      }
    }, stepDuration * 4);
  }

  function executeScanRequest() {
    const formData = new FormData();
    if (activeSampleType) {
      formData.append('sample_type', activeSampleType);
    } else if (currentFile) {
      formData.append('apk_file', currentFile);
    }

    fetch('/scan', {
      method: 'POST',
      body: formData
    })
      .then(async response => {
        const contentType = response.headers.get('content-type') || '';
        let data = null;

        if (contentType.includes('application/json')) {
          try {
            data = await response.json();
          } catch (_) {
            data = null;
          }
        } else {
          const rawText = await response.text();
          try {
            data = JSON.parse(rawText);
          } catch (_) {
            if (!response.ok) {
              if (response.status === 413) {
                throw new Error('The uploaded file exceeds the server maximum upload limit (HTTP 413). Please choose a smaller APK.');
              }
              throw new Error(`Server returned error (${response.status}: ${response.statusText || 'Request failed'}).`);
            }
            throw new Error('Received an unexpected response format from the server.');
          }
        }

        if (!response.ok || !data?.success) {
          throw new Error(data?.error || `Scan error (${response.status}: ${response.statusText || 'Failed'})`);
        }

        return data;
      })
      .then(data => {
        scanningCard.classList.add('hidden');
        renderResults(data);
      })
      .catch(err => {
        scanningCard.classList.add('hidden');
        uploadCard.classList.remove('hidden');
        showError(err.message || 'Network connection failed. Please retry.');
      });
  }

  // =================================================================
  // 5. RESULTS RENDERING
  // =================================================================
  function renderResults(data) {
    // Fill metadata strip
    document.getElementById('result-filename').textContent = data.filename || 'app.apk';
    document.getElementById('result-package').textContent = data.package_name || 'com.example.app';
    document.getElementById('result-size').textContent = `${(data.app_size_kb || 0).toLocaleString()} KB`;

    // Verdict Badge
    const verdictBadge = document.getElementById('verdict-badge');
    const riskBadge = document.getElementById('risk-level-badge');
    const vText = (data.verdict || 'BENIGN').toUpperCase();

    verdictBadge.textContent = vText;
    verdictBadge.className = 'verdict-badge';
    riskBadge.textContent = `${data.risk_level || 'SAFE'} RISK`;

    if (vText === 'BENIGN') {
      verdictBadge.classList.add('badge-safe');
    } else if (vText === 'ADWARE') {
      verdictBadge.classList.add('badge-adware');
    } else {
      verdictBadge.classList.add('badge-malware');
    }

    // Circular Confidence Ring Animation
    animateRing(data.confidence || 90.0, vText);

    // Probability Distribution Bars
    animateProbabilityBars(data.probabilities || {});

    // Feature Summary Grid
    const summary = data.feature_summary || {};
    document.getElementById('summary-total-perms').textContent = summary.total_permissions || 0;
    document.getElementById('summary-high-perms').textContent = summary.high_risk_count || 0;
    document.getElementById('summary-api-count').textContent = summary.api_calls_detected || 0;
    document.getElementById('summary-ad-sdks').textContent = summary.ad_sdks_detected || 0;

    // Render Explainability Content
    renderExplainability(data);

    // Show Results Card
    resultsCard.classList.remove('hidden');
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // =================================================================
  // 6. SVG CIRCULAR PROGRESS RING
  // =================================================================
  function animateRing(percentage, verdict) {
    const ringCircle = document.getElementById('ring-progress-circle');
    const ringVal = document.getElementById('ring-confidence-val');

    // Circumference = 2 * PI * 42 ~= 263.89
    const circumference = 263.89;
    const offset = circumference - (percentage / 100) * circumference;

    // Set ring color matching verdict
    if (verdict === 'BENIGN') {
      ringCircle.style.stroke = 'var(--safe-green)';
    } else if (verdict === 'ADWARE') {
      ringCircle.style.stroke = 'var(--danger-red)';
    } else {
      ringCircle.style.stroke = 'var(--warning-orange)';
    }

    // Animate stroke offset
    ringCircle.style.strokeDashoffset = offset;

    // Numerical counter animation
    let current = 0;
    const duration = 1000; // ms
    const stepTime = 20;
    const totalSteps = duration / stepTime;
    const increment = percentage / totalSteps;

    const counterInterval = setInterval(() => {
      current += increment;
      if (current >= percentage) {
        current = percentage;
        clearInterval(counterInterval);
      }
      ringVal.textContent = `${current.toFixed(1)}%`;
    }, stepTime);
  }

  function animateProbabilityBars(probs) {
    const benignVal = probs.Benign || 0;
    const adwareVal = probs.Adware || 0;
    const malwareVal = probs.Malware || 0;

    document.getElementById('prob-benign-text').textContent = `${benignVal.toFixed(1)}%`;
    document.getElementById('prob-adware-text').textContent = `${adwareVal.toFixed(1)}%`;
    document.getElementById('prob-malware-text').textContent = `${malwareVal.toFixed(1)}%`;

    setTimeout(() => {
      document.getElementById('prob-benign-fill').style.width = `${benignVal}%`;
      document.getElementById('prob-adware-fill').style.width = `${adwareVal}%`;
      document.getElementById('prob-malware-fill').style.width = `${malwareVal}%`;
    }, 100);
  }

  // =================================================================
  // 7. EXPLAINABILITY SECTION RENDERING
  // =================================================================
  function renderExplainability(data) {
    const perms = data.risk_permissions || [];
    const chartContainer = document.getElementById('permission-bar-chart');
    const tableBody = document.getElementById('risk-table-body');
    const apisList = document.getElementById('suspicious-apis-list');
    const sdksList = document.getElementById('ad-sdks-list');

    // 1. Clear previous content
    chartContainer.innerHTML = '';
    tableBody.innerHTML = '';
    apisList.innerHTML = '';
    sdksList.innerHTML = '';

    // 2. Build Horizontal Bar Chart (Top Permissions)
    if (perms.length === 0) {
      chartContainer.innerHTML = '<p class="text-muted">No high-risk permissions detected for this application.</p>';
    } else {
      perms.forEach(item => {
        const row = document.createElement('div');
        row.className = 'chart-bar-row';

        let riskClass = 'bar-low';
        if (item.risk === 'HIGH') riskClass = 'bar-high';
        else if (item.risk === 'MEDIUM') riskClass = 'bar-medium';

        row.innerHTML = `
          <span class="chart-bar-label" title="${item.name}">${item.name}</span>
          <div class="chart-bar-track">
            <div class="chart-bar-fill ${riskClass}" style="width: 0%;" data-pct="${item.percentage}"></div>
          </div>
          <span class="chart-bar-value">${item.percentage}%</span>
        `;
        chartContainer.appendChild(row);
      });

      // Animate widths shortly after DOM insertion
      setTimeout(() => {
        chartContainer.querySelectorAll('.chart-bar-fill').forEach(bar => {
          bar.style.width = `${bar.getAttribute('data-pct')}%`;
        });
      }, 150);
    }

    // 3. Build Risk Permissions Table
    if (perms.length === 0) {
      const emptyTr = document.createElement('tr');
      emptyTr.innerHTML = '<td colspan="4" class="text-center">No explicit dangerous permissions declared.</td>';
      tableBody.appendChild(emptyTr);
    } else {
      perms.forEach(item => {
        const tr = document.createElement('tr');
        let riskClass = 'risk-low';
        if (item.risk === 'HIGH') riskClass = 'risk-high';
        else if (item.risk === 'MEDIUM') riskClass = 'risk-medium';

        tr.innerHTML = `
          <td><strong>${item.name}</strong></td>
          <td><span class="risk-pill ${riskClass}">${item.risk}</span></td>
          <td>${item.weight.toFixed(2)}</td>
          <td>
            <div class="prob-track" style="height: 8px;">
              <div class="prob-fill ${item.risk === 'HIGH' ? 'fill-adware' : item.risk === 'MEDIUM' ? 'fill-malware' : 'fill-benign'}" style="width: ${item.percentage}%"></div>
            </div>
          </td>
        `;
        tableBody.appendChild(tr);
      });
    }

    // 4. Build Suspicious APIs List
    const apis = data.suspicious_apis || [];
    if (apis.length === 0) {
      apisList.innerHTML = '<span class="tag">No suspicious reflection or tracking APIs detected</span>';
    } else {
      apis.forEach(api => {
        const tag = document.createElement('span');
        tag.className = 'tag tag-danger';
        tag.textContent = api;
        apisList.appendChild(tag);
      });
    }

    // 5. Build Ad SDKs List
    const sdks = data.ad_sdks || [];
    if (sdks.length === 0) {
      sdksList.innerHTML = '<span class="tag">No commercial Ad SDK signatures identified</span>';
    } else {
      sdks.forEach(sdk => {
        const tag = document.createElement('span');
        tag.className = 'tag tag-warning';
        tag.textContent = sdk;
        sdksList.appendChild(tag);
      });
    }
  }

  // Toggle Explainability Visibility
  toggleExplainBtn.addEventListener('click', () => {
    const isHidden = explainabilityCard.classList.contains('hidden');
    if (isHidden) {
      explainabilityCard.classList.remove('hidden');
      explainabilityCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
      toggleExplainBtn.querySelector('.btn-text').textContent = 'Hide Explainability Details';
    } else {
      explainabilityCard.classList.add('hidden');
      toggleExplainBtn.querySelector('.btn-text').textContent = 'View Explainability & Risk Weights';
    }
  });

  // =================================================================
  // 8. RESET FUNCTION
  // =================================================================
  scanAnotherBtn.addEventListener('click', () => {
    resetScan();
  });

  function resetScan() {
    resultsCard.classList.add('hidden');
    explainabilityCard.classList.add('hidden');
    scanningCard.classList.add('hidden');
    uploadCard.classList.remove('hidden');

    resetFileInput();
    resetStepper();

    uploadCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // =================================================================
  // 9. ERROR HANDLING
  // =================================================================
  function showError(msg) {
    errorMessage.textContent = msg;
    errorAlert.classList.remove('hidden');
  }

  function hideError() {
    errorAlert.classList.add('hidden');
  }

  retryBtn.addEventListener('click', () => {
    hideError();
    if (currentFile || activeSampleType) {
      startScanPipeline();
    }
  });
});
