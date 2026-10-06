document.addEventListener("DOMContentLoaded", () => {
    const urlInput = document.getElementById("url-input");
    const scanButton = document.getElementById("scan-button");
    const statusElement = document.getElementById("status");
    const resultsSection = document.getElementById("results");

    const overallRiskLevel = document.getElementById(
        "overall-risk-level"
    );

    const overallRiskScore = document.getElementById(
        "overall-risk-score"
    );

    const totalFindings = document.getElementById(
        "total-findings"
    );

    const statusCode = document.getElementById(
        "status-code"
    );

    const findingsContainer = document.getElementById(
        "findings"
    );

    const historyContainer = document.getElementById(
        "scan-history"
    );

    const refreshHistoryButton = document.getElementById(
        "refresh-history"
    );

    const assistantQuestion = document.getElementById(
        "assistant-question"
    );

    const assistantButton = document.getElementById(
        "assistant-button"
    );

    const assistantLoading = document.getElementById(
        "assistant-loading"
    );

    const assistantError = document.getElementById(
        "assistant-error"
    );

    const assistantResult = document.getElementById(
        "assistant-result"
    );

    const assistantAnswerText = document.getElementById(
        "assistant-answer-text"
    );

    const assistantSourcesList = document.getElementById(
        "assistant-sources-list"
    );

    const findingsById = new Map();


    function formatRiskLevel(level) {
        if (!level) {
            return "-";
        }

        const labels = {
            very_low: "Very Low",
            low: "Low",
            medium: "Medium",
            high: "High",
            very_high: "Very High",
            critical: "Critical",
        };

        return labels[level] || level;
    }


    function escapeHtml(value) {
        if (
            value === null ||
            value === undefined
        ) {
            return "";
        }

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }


    function updateRiskSummary(summary) {
        const levels = [
            "critical",
            "very_high",
            "high",
            "medium",
            "low",
            "very_low",
        ];

        for (const level of levels) {
            const element = document.getElementById(
                `${level.replace("_", "-")}-count`
            );

            if (element) {
                element.textContent =
                    summary[level] || 0;
            }
        }
    }


    function buildFindingQuestion(finding) {
        return `
Explain the following CyberSentinel security finding.

Finding ID: ${finding.id}
Title: ${finding.title}
Severity: ${finding.severity}
Category: ${finding.category}
Risk score: ${finding.risk_score}
Risk level: ${finding.risk_level}

Evidence:
${finding.evidence}

Current recommendation:
${finding.recommendation}

Explain:
1. What this finding means.
2. Why it matters from a security perspective.
3. What risks it may introduce.
4. How it can be mitigated.

Base the explanation on the available security knowledge.
Do not invent evidence that is not present in the finding.
        `.trim();
    }


    function renderFindings(findings) {
        findingsContainer.innerHTML = "";

        findingsById.clear();

        if (
            !findings ||
            findings.length === 0
        ) {
            findingsContainer.innerHTML = `
                <div class="no-findings">
                    <strong>
                        No security findings detected.
                    </strong>

                    <span>
                        No issues were identified by
                        the current scanners.
                    </span>
                </div>
            `;

            return;
        }

        for (const finding of findings) {
            findingsById.set(
                finding.id,
                finding
            );

            const severity = escapeHtml(
                finding.severity ||
                "informational"
            );

            const riskLevel = escapeHtml(
                finding.risk_level ||
                "very_low"
            );

            const findingId = escapeHtml(
                finding.id
            );

            const card =
                document.createElement("article");

            card.className =
                `finding-card risk-${riskLevel}`;

            card.innerHTML = `
                <div class="finding-header">

                    <div>
                        <span class="finding-category">
                            ${escapeHtml(
                                finding.category
                            )}
                        </span>

                        <h3>
                            ${escapeHtml(
                                finding.title
                            )}
                        </h3>
                    </div>

                    <span
                        class="severity-badge severity-${severity}"
                    >
                        ${severity}
                    </span>

                </div>


                <div class="finding-risk">

                    <div>
                        <span>Risk</span>

                        <strong>
                            ${formatRiskLevel(
                                finding.risk_level
                            )}
                        </strong>
                    </div>


                    <div>
                        <span>Score</span>

                        <strong>
                            ${finding.risk_score ?? 0}
                        </strong>
                    </div>


                    <div>
                        <span>Likelihood</span>

                        <strong>
                            ${finding.likelihood ?? 0}/5
                        </strong>
                    </div>


                    <div>
                        <span>Impact</span>

                        <strong>
                            ${finding.impact ?? 0}/5
                        </strong>
                    </div>

                </div>


                <div class="finding-content">

                    <div>
                        <h4>Evidence</h4>

                        <p>
                            ${escapeHtml(
                                finding.evidence
                            )}
                        </p>
                    </div>


                    <div>
                        <h4>Recommendation</h4>

                        <p>
                            ${escapeHtml(
                                finding.recommendation
                            )}
                        </p>
                    </div>

                </div>


                <div class="finding-actions">

                    <button
                        type="button"
                        class="explain-finding-button"
                        data-finding-id="${findingId}"
                    >
                        Explain with Assistant
                    </button>

                </div>


                <div
                    class="finding-assistant-result hidden"
                    data-result-for="${findingId}"
                ></div>
            `;

            findingsContainer.appendChild(card);
        }
    }


    function renderScanResult(data) {
        const overallRisk =
            data.overall_risk || {};

        overallRiskLevel.textContent =
            formatRiskLevel(
                overallRisk.level
            );

        overallRiskScore.textContent =
            `Score: ${overallRisk.score ?? 0}`;

        totalFindings.textContent =
            data.total_findings ?? 0;

        statusCode.textContent =
            data.status_code ?? "-";

        updateRiskSummary(
            data.risk_summary || {}
        );

        renderFindings(
            data.findings || []
        );

        resultsSection.classList.remove(
            "hidden"
        );
    }


    async function runScan() {
        const url = urlInput.value.trim();

        if (!url) {
            statusElement.textContent =
                "Please enter a URL.";

            return;
        }

        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";

        statusElement.textContent =
            "Running security analysis...";

        resultsSection.classList.add(
            "hidden"
        );

        try {
            const response = await fetch(
                "/scan",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",
                    },

                    body: JSON.stringify({
                        url: url,
                    }),
                }
            );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.detail ||
                    "Scan failed."
                );
            }

            renderScanResult(data);

            await loadHistory();

            statusElement.textContent =
                "Scan completed successfully.";

        } catch (error) {
            statusElement.textContent =
                error.message ||
                "An unexpected error occurred.";

            resultsSection.classList.add(
                "hidden"
            );

        } finally {
            scanButton.disabled = false;
            scanButton.textContent = "Scan";
        }
    }


    scanButton.addEventListener(
        "click",
        runScan
    );


    urlInput.addEventListener(
        "keydown",
        (event) => {
            if (event.key === "Enter") {
                event.preventDefault();

                runScan();
            }
        }
    );


    function renderHistory(scans) {
        historyContainer.innerHTML = "";

        if (
            !scans ||
            scans.length === 0
        ) {
            historyContainer.innerHTML = `
                <p class="history-empty">
                    No scans found.
                </p>
            `;

            return;
        }

        for (const scan of scans) {
            const item =
                document.createElement("div");

            item.className =
                "history-item";

            const date =
                new Date(
                    scan.created_at
                ).toLocaleString();

            item.innerHTML = `
                <div>

                    <strong>
                        ${escapeHtml(
                            scan.url
                        )}
                    </strong>

                    <span>
                        ${escapeHtml(date)}
                    </span>

                </div>


                <div class="history-meta">

                    <span>
                        HTTP
                        ${escapeHtml(
                            scan.status_code
                        )}
                    </span>

                    <span>
                        ${escapeHtml(
                            scan.total_findings
                        )}
                        finding(s)
                    </span>

                </div>
            `;

            historyContainer.appendChild(
                item
            );
        }
    }


    async function loadHistory() {
        try {
            const response =
                await fetch("/scans");

            if (!response.ok) {
                throw new Error(
                    "Could not load scan history."
                );
            }

            const scans =
                await response.json();

            renderHistory(scans);

        } catch (error) {
            historyContainer.innerHTML = `
                <p class="history-error">
                    ${escapeHtml(
                        error.message
                    )}
                </p>
            `;
        }
    }


    if (refreshHistoryButton) {
        refreshHistoryButton.addEventListener(
            "click",
            loadHistory
        );
    }


    function showAssistantError(
        message
    ) {
        assistantError.textContent =
            message;

        assistantError.classList.remove(
            "hidden"
        );
    }


    function hideAssistantError() {
        assistantError.textContent = "";

        assistantError.classList.add(
            "hidden"
        );
    }


    function renderAssistantSources(
        sources
    ) {
        assistantSourcesList.innerHTML =
            "";

        if (
            !sources ||
            sources.length === 0
        ) {
            assistantSourcesList.innerHTML = `
                <div class="assistant-empty-source">
                    No relevant sources were returned.
                </div>
            `;

            return;
        }

        for (const source of sources) {
            const sourceElement =
                document.createElement(
                    "div"
                );

            sourceElement.className =
                "assistant-source";

            const distance =
                Number(
                    source.distance
                );

            sourceElement.innerHTML = `
                <div class="assistant-source-main">

                    <span class="assistant-source-name">
                        ${escapeHtml(
                            source.source
                        )}
                    </span>

                    <span class="assistant-source-chunk">
                        Chunk
                        ${escapeHtml(
                            source.chunk_index
                        )}
                    </span>

                </div>

                <span class="assistant-source-distance">
                    Distance
                    ${
                        Number.isFinite(
                            distance
                        )
                            ? distance.toFixed(3)
                            : "-"
                    }
                </span>
            `;

            assistantSourcesList.appendChild(
                sourceElement
            );
        }
    }


    function renderAssistantMarkdown(markdown) {
        if (!markdown) {
            return "";
        }

        let html = escapeHtml(markdown);

        html = html.replace(
            /\\([\\`*_[\]{}()#+.!-])/g,
            "$1"
        );

        html = html.replace(
            /^### (.+)$/gm,
            "<h4>$1</h4>"
        );

        html = html.replace(
            /^## (.+)$/gm,
            "<h3>$1</h3>"
        );

        html = html.replace(
            /^# (.+)$/gm,
            "<h2>$1</h2>"
        );

        html = html.replace(
            /\*\*(.+?)\*\*/g,
            "<strong>$1</strong>"
        );

        html = html.replace(
            /`([^`]+)`/g,
            "<code>$1</code>"
        );

        html = html.replace(
            /^- (.+)$/gm,
            "<li>$1</li>"
        );

        html = html.replace(
            /(<li>.*<\/li>)/gs,
            "<ul>$1</ul>"
        );

        html = html.replace(
            /\n{2,}/g,
            "</p><p>"
        );

        html = `<p>${html}</p>`;

        html = html.replace(
            /<p>(<h[234]>)/g,
            "$1"
        );

        html = html.replace(
            /(<\/h[234]>)<\/p>/g,
            "$1"
        );

        html = html.replace(
            /<p>(<ul>)/g,
            "$1"
        );

        html = html.replace(
            /(<\/ul>)<\/p>/g,
            "$1"
        );

        return html;
    }


    async function askAssistant(
        question = null
    ) {
        const assistantQuestionText =
            (
                question !== null
                    ? question
                    : assistantQuestion.value
            ).trim();

        if (!assistantQuestionText) {
            showAssistantError(
                "Please enter a security question."
            );

            return;
        }

        hideAssistantError();

        assistantLoading.classList.remove(
            "hidden"
        );

        assistantResult.classList.add(
            "hidden"
        );

        assistantButton.disabled = true;

        assistantButton.textContent =
            "Analyzing...";

        try {
            const response =
                await fetch(
                    "/assistant",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json",
                        },

                        body: JSON.stringify({
                            question:
                                assistantQuestionText,

                            top_k: 3,
                        }),
                    }
                );

            const data =
                await response.json();

            if (!response.ok) {
                throw new Error(
                    data.detail ||
                    "The assistant request failed."
                );
            }

            assistantAnswerText.innerHTML =
                renderAssistantMarkdown(
                    data.answer ||
                    "No answer returned."
                );

            renderAssistantSources(
                data.sources
            );

            assistantResult.classList.remove(
                "hidden"
            );

        } catch (error) {
            showAssistantError(
                error.message ||
                "An unexpected error occurred."
            );

        } finally {
            assistantLoading.classList.add(
                "hidden"
            );

            assistantButton.disabled = false;

            assistantButton.textContent =
                "Ask Assistant";
        }
    }


    assistantButton.addEventListener(
        "click",
        () => {
            askAssistant();
        }
    );


    assistantQuestion.addEventListener(
        "keydown",
        (event) => {
            if (
                event.key === "Enter" &&
                !event.shiftKey
            ) {
                event.preventDefault();

                askAssistant();
            }
        }
    );


    async function explainFinding(
        finding
    ) {
        const question =
            buildFindingQuestion(
                finding
            );

        assistantQuestion.value =
            question;

        assistantQuestion.scrollIntoView({
            behavior: "smooth",
            block: "center",
        });

        await askAssistant(
            question
        );
    }


    findingsContainer.addEventListener(
        "click",
        async (event) => {
            const button =
                event.target.closest(
                    ".explain-finding-button"
                );

            if (!button) {
                return;
            }

            const findingId =
                button.dataset.findingId;

            const finding =
                findingsById.get(
                    findingId
                );

            if (!finding) {
                showAssistantError(
                    "The selected finding could not be found."
                );

                return;
            }

            button.disabled = true;

            button.textContent =
                "Explaining...";

            try {
                await explainFinding(
                    finding
                );
            } finally {
                button.disabled = false;

                button.textContent =
                    "Explain with Assistant";
            }
        }
    );


    loadHistory();
});