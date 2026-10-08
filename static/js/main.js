/**
 * PHISH//TRAP - CYBERSECURITY OPERATIONS CENTER JAVASCRIPT
 * Real-time clocks, offline canvas visualizations, scanner progression, and HUD controls.
 */

document.addEventListener('DOMContentLoaded', () => {
    initLiveClock();
    initMobileSidebar();
    initScanAnimation();
    initCanvasCharts();
});

/* --------------------------------------------------------------------------
   1. LIVE UTC & LOCAL DIGITAL CLOCK
   -------------------------------------------------------------------------- */
function initLiveClock() {
    const clockEl = document.getElementById('socLiveClock');
    if (!clockEl) return;

    function update() {
        const now = new Date();
        const utcHours = String(now.getUTCHours()).padStart(2, '0');
        const utcMinutes = String(now.getUTCMinutes()).padStart(2, '0');
        const utcSeconds = String(now.getUTCSeconds()).padStart(2, '0');
        clockEl.textContent = `${utcHours}:${utcMinutes}:${utcSeconds} UTC`;
    }

    update();
    setInterval(update, 1000);
}

/* --------------------------------------------------------------------------
   2. MOBILE SIDEBAR DRAWER TOGGLE
   -------------------------------------------------------------------------- */
function initMobileSidebar() {
    const toggleBtn = document.getElementById('menuToggleBtn');
    const sidebar = document.getElementById('cyberSidebar');
    if (!toggleBtn || !sidebar) return;

    toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    // Close when clicking outside on mobile
    document.addEventListener('click', (e) => {
        if (sidebar.classList.contains('open') && 
            !sidebar.contains(e.target) && 
            !toggleBtn.contains(e.target)) {
            sidebar.classList.remove('open');
        }
    });
}

/* --------------------------------------------------------------------------
   3. URL SCANNING PROGRESSION ANIMATION (CLASSIFY PAGE)
   -------------------------------------------------------------------------- */
function initScanAnimation() {
    const scanForm = document.getElementById('urlScanForm');
    const scanHud = document.getElementById('scanProgressHud');
    const scanButton = document.getElementById('startScanBtn');
    if (!scanForm || !scanHud) return;

    scanForm.addEventListener('submit', (e) => {
        const inputUrl = document.getElementById('scanUrlInput');
        if (!inputUrl || !inputUrl.value.trim()) return;

        // Prevent instant submit to allow 900ms visual scanner progression
        if (!scanForm.dataset.scanning) {
            e.preventDefault();
            scanForm.dataset.scanning = 'true';
            scanHud.style.display = 'block';
            if (scanButton) {
                scanButton.disabled = true;
                scanButton.innerHTML = '<span class="status-dot cyan pulse"></span> SCANNING IN PROGRESS...';
            }

            const items = scanHud.querySelectorAll('.scan-progress-item');
            let delay = 0;
            items.forEach((item, index) => {
                setTimeout(() => {
                    item.classList.add('done');
                    const check = item.querySelector('.check');
                    if (check) check.textContent = '✓';
                }, delay);
                delay += 120;
            });

            // Submit after visual progression completes
            setTimeout(() => {
                scanForm.submit();
            }, delay + 180);
        }
    });

    // Reset state on browser back/forward cache navigation
    window.addEventListener('pageshow', () => {
        scanForm.dataset.scanning = '';
        if (scanButton) {
            scanButton.disabled = false;
            scanButton.innerHTML = '⚡ START THREAT SCAN';
        }
        if (scanHud) {
            scanHud.style.display = 'none';
            scanHud.querySelectorAll('.scan-progress-item').forEach(item => {
                item.classList.remove('done');
                const check = item.querySelector('.check');
                if (check) check.textContent = '○';
            });
        }
    });
}

/* --------------------------------------------------------------------------
   4. OFFLINE CANVAS CHARTS (NO EXTERNAL LIBS REQUIRED)
   -------------------------------------------------------------------------- */
function initCanvasCharts() {
    // 4.1 Threat Distribution Donut
    const donutCanvas = document.getElementById('threatDonutChart');
    if (donutCanvas) {
        const safe = parseInt(donutCanvas.dataset.safe || '0', 10);
        const suspicious = parseInt(donutCanvas.dataset.suspicious || '0', 10);
        const phishing = parseInt(donutCanvas.dataset.phishing || '0', 10);
        drawThreatDonut(donutCanvas, safe, suspicious, phishing);
    }

    // 4.2 Threat Activity Timeline
    const timelineCanvas = document.getElementById('threatTimelineChart');
    if (timelineCanvas) {
        drawActivityTimeline(timelineCanvas);
    }
}

/**
 * Draw High-Tech Glowing Donut Chart
 */
function drawThreatDonut(canvas, safe, suspicious, phishing) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 240;
    const height = canvas.height = canvas.parentElement.clientHeight || 240;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) * 0.72;
    const lineWidth = 20;

    const total = safe + suspicious + phishing;
    ctx.clearRect(0, 0, width, height);

    if (total === 0) {
        // Empty state ring
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = lineWidth;
        ctx.stroke();

        ctx.font = '12px "JetBrains Mono", monospace';
        ctx.fillStyle = '#64748b';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('NO DATA', centerX, centerY);
        return;
    }

    const slices = [
        { count: safe, color: '#10b981', label: 'SAFE' },
        { count: suspicious, color: '#f59e0b', label: 'SUSPICIOUS' },
        { count: phishing, color: '#f43f5e', label: 'PHISHING' }
    ];

    let startAngle = -0.5 * Math.PI;

    slices.forEach(slice => {
        if (slice.count === 0) return;
        const sliceAngle = (slice.count / total) * 2 * Math.PI;

        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
        ctx.strokeStyle = slice.color;
        ctx.lineWidth = lineWidth;
        ctx.lineCap = 'butt';
        ctx.stroke();

        startAngle += sliceAngle;
    });

    // Center Text
    ctx.font = 'bold 22px "JetBrains Mono", monospace';
    ctx.fillStyle = '#f8fafc';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total.toString(), centerX, centerY - 6);

    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#64748b';
    ctx.fillText('TOTAL SCANS', centerX, centerY + 14);
}

/**
 * Draw Activity Timeline Canvas
 */
function drawActivityTimeline(canvas) {
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 600;
    const height = canvas.height = canvas.parentElement.clientHeight || 220;
    
    ctx.clearRect(0, 0, width, height);

    // Padding
    const pLeft = 40;
    const pRight = 20;
    const pTop = 20;
    const pBottom = 30;
    const plotWidth = width - pLeft - pRight;
    const plotHeight = height - pTop - pBottom;

    // Draw horizontal grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
        const y = pTop + (plotHeight / 4) * i;
        ctx.beginPath();
        ctx.moveTo(pLeft, y);
        ctx.lineTo(width - pRight, y);
        ctx.stroke();
    }

    // Parse data points from DOM or render representative timeline
    const dataPoints = [4, 7, 3, 12, 8, 15, 9, 14, 20, 16, 22, 19];
    const maxVal = Math.max(...dataPoints, 25);
    const stepX = plotWidth / (dataPoints.length - 1);

    // Gradient fill under curve
    const gradient = ctx.createLinearGradient(0, pTop, 0, height - pBottom);
    gradient.addColorStop(0, 'rgba(0, 242, 254, 0.25)');
    gradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

    ctx.beginPath();
    dataPoints.forEach((val, i) => {
        const x = pLeft + i * stepX;
        const y = pTop + plotHeight - (val / maxVal) * plotHeight;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });

    ctx.lineTo(pLeft + plotWidth, pTop + plotHeight);
    ctx.lineTo(pLeft, pTop + plotHeight);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw cyan line stroke
    ctx.beginPath();
    dataPoints.forEach((val, i) => {
        const x = pLeft + i * stepX;
        const y = pTop + plotHeight - (val / maxVal) * plotHeight;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#00f2fe';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Draw points
    dataPoints.forEach((val, i) => {
        const x = pLeft + i * stepX;
        const y = pTop + plotHeight - (val / maxVal) * plotHeight;
        ctx.beginPath();
        ctx.arc(x, y, 3.5, 0, 2 * Math.PI);
        ctx.fillStyle = '#06090f';
        ctx.fill();
        ctx.strokeStyle = '#00f2fe';
        ctx.lineWidth = 2;
        ctx.stroke();
    });

    // Time labels
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillStyle = '#64748b';
    ctx.textAlign = 'center';
    ctx.fillText('00:00', pLeft, height - 10);
    ctx.fillText('06:00', pLeft + plotWidth * 0.25, height - 10);
    ctx.fillText('12:00', pLeft + plotWidth * 0.5, height - 10);
    ctx.fillText('18:00', pLeft + plotWidth * 0.75, height - 10);
    ctx.fillText('NOW', pLeft + plotWidth, height - 10);
}
