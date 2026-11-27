
const API_BASE = "http://127.0.0.1:5000";

const scanForm = document.getElementById("scanForm");
const scanButton = document.getElementById("scanButton");
const scanMessage = document.getElementById("scanMessage");
const scanProgress = document.getElementById("scanProgress");
const findingsBody = document.getElementById("findingsBody");

let activeScanId = null;
let pollingTimer = null;

// Display messages
function showMessage(message, type) {
    scanMessage.textContent = message;
    scanMessage.className = `message ${type}`;
}

// Update scan progress
function updateProgress(status) {
    const progressValues = {
        queued: 5,
        spider_scanning: 25,
        passive_scanning: 50,
        active_scanning: 75,
        collecting_findings: 90,
        completed: 100,
        failed: 100
    };

    const labels = {
        queued: "Scan queued",
        spider_scanning: "Spider scanning...",
        passive_scanning: "Passive scanning...",
        active_scanning: "Active scanning...",
        collecting_findings: "Collecting findings...",
        completed: "Scan completed",
        failed: "Scan failed"
    };

    document.getElementById("scanStatus").textContent =
        labels[status] || status;

    document.getElementById("progressBar").style.width =
        `${progressValues[status] ?? 5}%`;
}

// Create a table cell safely
function createCell(text) {
    const cell = document.createElement("td");
    cell.textContent = text || "N/A";
    return cell;
}

// Create a section inside expanded vulnerability details
function createDetailSection(title, content) {
    const section = document.createElement("div");
    section.className = "detail-section";

    const heading = document.createElement("h4");
    heading.textContent = title;

    const paragraph = document.createElement("p");
    paragraph.textContent = content || "No information available.";

    section.append(heading, paragraph);

    return section;
}

// Start a new scan

async function startScan(event) {
    event.preventDefault();

    const targetUrl = document.getElementById("targetUrl").value.trim();
    const authorized = document.getElementById("authorized").checked;
    const scanMode = document.getElementById("scanMode").value;

    if (!targetUrl) {
        showMessage("Please enter a target URL.", "error");
        return;
    }

    if (!authorized) {
        showMessage(
            "Please confirm that you have permission to scan this target.",
            "error"
        );
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Starting...";
    showMessage("Connecting to scanner backend...", "success");

    try {
        const response = await fetch(`${API_BASE}/api/scans`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                target_url: targetUrl,
                authorized: true,
                scan_mode: scanMode
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || "Unable to start scan");
        }

        activeScanId = result.scan.id;

        document.getElementById("scanId").textContent =
            `Scan ID: ${activeScanId}`;

        scanProgress.hidden = false;

        updateProgress(result.scan.status);

        // Clear previous findings
        findingsBody.replaceChildren();

        showMessage(
            `${scanMode === "quick" ? "Quick Scan" : "Thorough Scan"} started successfully!`,
            "success"
        );

        await loadHistory();
        await loadDashboard();

        if (pollingTimer) {
            clearInterval(pollingTimer);
        }

        const currentScanId = activeScanId;

        pollingTimer = setInterval(() => {
            checkScanStatus(currentScanId);
        }, 3000);

    } catch (error) {
        showMessage(error.message, "error");
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Start Scan →";
    }
}

// Check scan status
async function checkScanStatus(scanId) {
    try {
        const response = await fetch(
            `${API_BASE}/api/scans/${scanId}/status`
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.error || "Unable to retrieve scan status"
            );
        }

        updateProgress(result.status);

        if (result.status === "completed") {
            clearInterval(pollingTimer);
            pollingTimer = null;

            showMessage(
                "Scan completed! Loading vulnerability findings...",
                "success"
            );

            await loadFindings(scanId);
            await loadDashboard();
            await loadHistory();

            showMessage(
                "Scan completed! Vulnerability findings are available below.",
                "success"
            );

        } else if (result.status === "failed") {
            clearInterval(pollingTimer);
            pollingTimer = null;

            showMessage(
                `Scan failed: ${result.error || "Unknown error"}`,
                "error"
            );

            await loadHistory();
        }

    } catch (error) {
        showMessage(error.message, "error");
    }
}

// Load and display vulnerability findings
async function loadFindings(scanId) {
    try {
        const response = await fetch(
            `${API_BASE}/api/scans/${scanId}/findings`
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.error || "Unable to load vulnerability findings"
            );
        }

        findingsBody.replaceChildren();

        const findings = result.findings || [];

        if (findings.length === 0) {
            const row = document.createElement("tr");
            const cell = createCell("No vulnerability findings available.");

            cell.colSpan = 4;
            row.appendChild(cell);
            findingsBody.appendChild(row);

            return;
        }

        findings.forEach((finding) => {
            // Main vulnerability row
            const row = document.createElement("tr");

            row.appendChild(createCell(finding.name));
            row.appendChild(createCell(finding.risk));
            row.appendChild(createCell(finding.confidence));
            row.appendChild(createCell(finding.url));

            findingsBody.appendChild(row);

            // Expandable details row
            const detailRow = document.createElement("tr");
            detailRow.className = "finding-detail-row";

            const detailCell = document.createElement("td");
            detailCell.colSpan = 4;
            detailCell.className = "finding-detail-cell";

            const details = document.createElement("details");
            details.className = "finding-details";

            const summary = document.createElement("summary");
            summary.textContent = "View description, solution and references";

            details.appendChild(summary);

            // Load detailed information only when expanded
            let detailsLoaded = false;

            details.addEventListener("toggle", () => {
                if (!details.open || detailsLoaded) {
                    return;
                }

                const content = document.createElement("div");
                content.className = "finding-detail-content";

                content.appendChild(
                    createDetailSection(
                        "Description",
                        finding.description
                    )
                );

                content.appendChild(
                    createDetailSection(
                        "Recommended Solution",
                        finding.solution
                    )
                );

                content.appendChild(
                    createDetailSection(
                        "References",
                        finding.reference
                    )
                );

                details.appendChild(content);
                detailsLoaded = true;
            });

            detailCell.appendChild(details);
            detailRow.appendChild(detailCell);

            findingsBody.appendChild(detailRow);
        });

    } catch (error) {
        showMessage(error.message, "error");
    }
}

// Load scan history
async function loadHistory() {
    try {
        const response = await fetch(`${API_BASE}/api/scans`);
        const result = await response.json();

        if (!response.ok) {
            throw new Error("Unable to load scan history");
        }

        const historyList = document.getElementById("historyList");
        historyList.replaceChildren();

        if (!result.scans || result.scans.length === 0) {
            historyList.textContent = "No scans available.";
            historyList.className = "empty-state";
            return;
        }

        historyList.className = "history-list";

        result.scans.slice().reverse().forEach(scan => {
            const item = document.createElement("div");
            item.className = "history-item";

            const details = document.createElement("div");

            const title = document.createElement("strong");
            title.textContent = `Scan #${scan.id}`;

            const target = document.createElement("small");
            target.textContent = scan.target_url;

            details.append(title, target);

            const status = document.createElement("span");
            status.className = "history-status";
            status.textContent = scan.status;

            item.append(details, status);
            historyList.appendChild(item);
        });

    } catch (error) {
        showMessage(error.message, "error");
    }
}

// Load dashboard statistics
// Load dashboard statistics and risk distribution

// Load dashboard statistics and risk distribution
async function loadDashboard() {
    try {
        const response = await fetch(`${API_BASE}/api/scans`);
        const result = await response.json();

        if (!response.ok) {
            throw new Error("Unable to load dashboard statistics");
        }

        let totalFindings = 0;
        let highRisk = 0;
        let completedScans = 0;

        const riskCounts = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0,
            Informational: 0
        };

        (result.scans || []).forEach(scan => {

            if (scan.status === "completed") {
                completedScans++;
            }

            (scan.findings || []).forEach(finding => {

                const risk = (finding.risk || "").toLowerCase();

                if (risk === "critical") {
                    riskCounts.Critical++;
                    totalFindings++;
                    highRisk++;

                } else if (risk === "high") {
                    riskCounts.High++;
                    totalFindings++;
                    highRisk++;

                } else if (risk === "medium") {
                    riskCounts.Medium++;
                    totalFindings++;

                } else if (risk === "low") {
                    riskCounts.Low++;
                    totalFindings++;

                } else if (risk === "informational") {
                    riskCounts.Informational++;
                    totalFindings++;
                }
            });
        });

        // Update dashboard cards
        document.getElementById("totalScans").textContent =
            result.count ?? result.scans.length;

        document.getElementById("totalFindings").textContent =
            totalFindings;

        document.getElementById("highRisk").textContent =
            highRisk;

        document.getElementById("completedScans").textContent =
            completedScans;

        // Render Risk Distribution
        const riskContainer =
            document.getElementById("riskDistribution");

        const maxCount = Math.max(
            ...Object.values(riskCounts),
            1
        );

        riskContainer.innerHTML = "";

        Object.entries(riskCounts).forEach(([risk, count]) => {

            const percentage = (count / maxCount) * 100;

            const item = document.createElement("div");
            item.className = "risk-item";

            const name = document.createElement("span");
            name.className = "risk-name";
            name.textContent = risk;

            const track = document.createElement("div");
            track.className = "risk-track";

            const fill = document.createElement("div");
            fill.className =
                `risk-fill risk-${risk.toLowerCase()}`;

            fill.style.width = `${percentage}%`;

            const number = document.createElement("span");
            number.className = "risk-count";
            number.textContent = count;

            track.appendChild(fill);
            item.append(name, track, number);

            riskContainer.appendChild(item);
        });

    } catch (error) {
        console.error("Dashboard loading error:", error);
        showMessage(error.message, "error");
    }
}

// Initialize dashboard
async function initializeDashboard() {
    await loadDashboard();
    await loadHistory();

    try {
        const response = await fetch(`${API_BASE}/api/scans`);
        const result = await response.json();

        if (!response.ok) {
            throw new Error("Unable to restore previous scan");
        }

        if (!result.scans || result.scans.length === 0) {
            return;
        }

        // Get the latest scan
        const latestScan = result.scans[result.scans.length - 1];

        activeScanId = latestScan.id;

        document.getElementById("scanId").textContent =
            `Scan ID: ${activeScanId}`;

        if (latestScan.status === "completed") {
            scanProgress.hidden = false;
            updateProgress("completed");

            await loadFindings(activeScanId);

        } else if (latestScan.status === "failed") {
            scanProgress.hidden = false;
            updateProgress("failed");

        } else {
            scanProgress.hidden = false;
            updateProgress(latestScan.status);

            pollingTimer = setInterval(() => {
                checkScanStatus(activeScanId);
            }, 3000);
        }

    } catch (error) {
        showMessage(error.message, "error");
    }
}

// Handle new scan form submission
scanForm.addEventListener("submit", startScan);

// Initialize dashboard
initializeDashboard();
