import * as core from "@actions/core";
import { context, getOctokit } from "@actions/github";
import * as fs from "fs/promises";
import "@actions/github/lib/utils.js";

//#region src/trivy.ts
/**
* This function is responsible for parsing the Trivy report and return a structure with it´s output.
*/
async function parseTrivyReport(reportPath) {
	try {
		const fileContents = await fs.readFile(reportPath, "utf-8");
		const report = JSON.parse(fileContents);
		if (!report.Results) throw new Error("Invalid Trivy report: missing Results field");
		if (!Array.isArray(report.Results)) throw new Error("Invalid Trivy report: Results must be an array");
		return report;
	} catch (error) {
		if (error instanceof Error) {
			if ("code" in error && error.code === "ENOENT") throw new Error(`Trivy report file not found: ${reportPath}`);
			if (error.name === "SyntaxError") throw new Error(`Invalid JSON in Trivy report file: ${reportPath}`);
			throw new Error(`Failed to parse Trivy report: ${error.message}`);
		}
		throw error;
	}
}

//#endregion
//#region src/issue.ts
const MAX_ISSUE_BODY_SIZE = 6e4;
const MAX_ISSUE_TITLE_LENGTH = 256;
/**
* Count vulnerabilities by severity
*/
function countBySeverity(report) {
	const counts = {
		CRITICAL: 0,
		HIGH: 0,
		MEDIUM: 0,
		LOW: 0,
		UNKNOWN: 0
	};
	for (const result of report.Results) {
		if (!result.Vulnerabilities) continue;
		for (const vuln of result.Vulnerabilities) {
			const severity = vuln.Severity?.toUpperCase() || "UNKNOWN";
			if (severity in counts) counts[severity]++;
			else counts.UNKNOWN++;
		}
	}
	return counts;
}
/**
* Get total vulnerability count
*/
function getTotalCount(counts) {
	return counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.UNKNOWN;
}
/**
* Group vulnerabilities by severity
*/
function groupBySeverity(vulnerabilities) {
	const groups = /* @__PURE__ */ new Map();
	for (const severity of [
		"CRITICAL",
		"HIGH",
		"MEDIUM",
		"LOW",
		"UNKNOWN"
	]) groups.set(severity, []);
	for (const vuln of vulnerabilities) {
		const severity = vuln.Severity?.toUpperCase() || "UNKNOWN";
		const group = groups.get(severity);
		if (group) group.push(vuln);
		else groups.get("UNKNOWN").push(vuln);
	}
	return groups;
}
/**
* Truncate text to specified length with ellipsis
*/
function truncateText(text, maxLength) {
	if (!text || text.length <= maxLength) return text || "N/A";
	return text.substring(0, maxLength) + "...";
}
/**
* Generate markdown table for vulnerabilities of a specific severity
*/
function generateVulnerabilityTable(vulnerabilities) {
	if (vulnerabilities.length === 0) return "";
	let table = "\n| Package | Vulnerability ID | Installed Version | Fixed Version | Description |\n";
	table += "|---------|------------------|-------------------|---------------|-------------|\n";
	for (const vuln of vulnerabilities) {
		const vulnId = vuln.PrimaryURL ? `[${vuln.VulnerabilityID}](${vuln.PrimaryURL})` : vuln.VulnerabilityID;
		const pkgName = vuln.PkgName || "N/A";
		const installedVersion = vuln.InstalledVersion || "N/A";
		const fixedVersion = vuln.FixedVersion || "Not Available";
		const description = truncateText(vuln.Description || vuln.Title || "No description available", 100);
		table += `| ${pkgName} | ${vulnId} | ${installedVersion} | ${fixedVersion} | ${description} |\n`;
	}
	return table;
}
/**
* Aggregate vulnerabilities by VulnerabilityID across all results
*/
function aggregateVulnerabilities(trivyReport) {
	const aggregated = /* @__PURE__ */ new Map();
	for (const result of trivyReport.Results) {
		if (!result.Vulnerabilities) continue;
		for (const vuln of result.Vulnerabilities) {
			const vulnId = vuln.VulnerabilityID;
			if (!aggregated.has(vulnId)) aggregated.set(vulnId, {
				vulnerabilityId: vulnId,
				severity: vuln.Severity || "UNKNOWN",
				title: vuln.Title || "",
				description: vuln.Description || "",
				references: vuln.References || [],
				primaryUrl: vuln.PrimaryURL,
				cweIds: vuln.CweIDs,
				publishedDate: vuln.PublishedDate,
				lastModifiedDate: vuln.LastModifiedDate,
				occurrences: []
			});
			aggregated.get(vulnId).occurrences.push({
				target: result.Target,
				pkgName: vuln.PkgName,
				installedVersion: vuln.InstalledVersion,
				fixedVersion: vuln.FixedVersion,
				type: result.Type,
				class: result.Class
			});
		}
	}
	return aggregated;
}
/**
* Search for an existing CVE issue by vulnerability ID
*/
async function findExistingCveIssue(octokit, owner, repo, vulnId) {
	try {
		const { data: issues } = await octokit.rest.issues.listForRepo({
			owner,
			repo,
			state: "open",
			creator: "github-actions[bot]",
			per_page: 100
		});
		const titlePrefix = `[Security] ${vulnId}:`;
		const existingIssue = issues.find((issue) => issue.title.startsWith(titlePrefix));
		return existingIssue ? existingIssue.number : null;
	} catch (error) {
		console.warn("Failed to search for existing CVE issues:", error);
		return null;
	}
}
/**
* Generate markdown report for a single CVE
*/
function generateCveMarkdownReport(vuln) {
	const timestamp = (/* @__PURE__ */ new Date()).toISOString();
	let markdown = `# ${{
		CRITICAL: "🔴",
		HIGH: "🟠",
		MEDIUM: "🟡",
		LOW: "🟢",
		UNKNOWN: "⚪"
	}[vuln.severity.toUpperCase()] || "⚪"} ${vuln.severity.toUpperCase()} Severity\n\n`;
	markdown += `## Vulnerability: ${vuln.vulnerabilityId}\n\n`;
	markdown += "### 📋 Description\n\n";
	markdown += `${vuln.description || "No description available"}\n\n`;
	if (vuln.title && vuln.title !== vuln.description) markdown += `**Title:** ${vuln.title}\n\n`;
	if (vuln.cweIds && vuln.cweIds.length > 0) markdown += `**CWE IDs:** ${vuln.cweIds.join(", ")}\n\n`;
	if (vuln.references && vuln.references.length > 0) {
		markdown += "### 🔗 References\n\n";
		for (const ref of vuln.references.slice(0, 10)) markdown += `- ${ref}\n`;
		if (vuln.references.length > 10) markdown += `\n*... and ${vuln.references.length - 10} more references*\n`;
		markdown += "\n";
	}
	markdown += "### 📦 Affected Packages\n\n";
	markdown += "| Target | Package | Installed Version | Fixed Version | Type | Class |\n";
	markdown += "|--------|---------|-------------------|---------------|------|-------|\n";
	for (const occ of vuln.occurrences) {
		const target = truncateText(occ.target, 40);
		const pkgName = occ.pkgName || "N/A";
		const installedVersion = occ.installedVersion || "N/A";
		const fixedVersion = occ.fixedVersion || "Not Available";
		const type = occ.type || "N/A";
		const classValue = occ.class || "N/A";
		markdown += `| ${target} | ${pkgName} | ${installedVersion} | ${fixedVersion} | ${type} | ${classValue} |\n`;
	}
	markdown += "\n";
	markdown += "---\n\n";
	if (vuln.publishedDate) markdown += `**Published:** ${vuln.publishedDate}\n\n`;
	if (vuln.lastModifiedDate) markdown += `**Last Modified:** ${vuln.lastModifiedDate}\n\n`;
	markdown += `*Report generated on: ${timestamp}*\n\n`;
	markdown += "*Powered by [Trivy](https://trivy.dev/)*\n";
	if (markdown.length > MAX_ISSUE_BODY_SIZE) markdown = markdown.substring(0, MAX_ISSUE_BODY_SIZE - 133) + "\n\n---\n\n⚠️ **Note:** This report was truncated due to size limitations. Please check the full Trivy report file for complete details.\n";
	return markdown;
}
/**
* Create issue title for a CVE
*/
function createCveIssueTitle(vuln) {
	const prefix = `[Security] ${vuln.vulnerabilityId}:`;
	const titleText = vuln.title || vuln.description || "Security vulnerability";
	const remainingSpace = MAX_ISSUE_TITLE_LENGTH - prefix.length - 1;
	if (titleText.length <= remainingSpace) return `${prefix} ${titleText}`;
	return `${prefix} ${titleText.substring(0, remainingSpace - 3)}...`;
}
/**
* Create or update a single CVE issue
*/
async function createOrUpdateCveIssue(octokit, owner, repo, vuln, labels) {
	const issueTitle = createCveIssueTitle(vuln);
	const markdownBody = generateCveMarkdownReport(vuln);
	const existingIssueNumber = await findExistingCveIssue(octokit, owner, repo, vuln.vulnerabilityId);
	if (existingIssueNumber) {
		await octokit.rest.issues.update({
			owner,
			repo,
			issue_number: existingIssueNumber,
			title: issueTitle,
			body: markdownBody,
			labels: labels.length > 0 ? labels : void 0
		});
		const timestamp = (/* @__PURE__ */ new Date()).toISOString();
		await octokit.rest.issues.createComment({
			owner,
			repo,
			issue_number: existingIssueNumber,
			body: `🔄 Report updated on ${timestamp}`
		});
		return {
			issueNumber: existingIssueNumber,
			issueUrl: `https://github.com/${owner}/${repo}/issues/${existingIssueNumber}`,
			vulnerabilitiesFound: true
		};
	}
	const { data: newIssue } = await octokit.rest.issues.create({
		owner,
		repo,
		title: issueTitle,
		body: markdownBody,
		labels: labels.length > 0 ? labels : void 0
	});
	return {
		issueNumber: newIssue.number,
		issueUrl: newIssue.html_url,
		vulnerabilitiesFound: true
	};
}
/**
* Close a CVE issue that no longer has vulnerabilities
*/
async function closeCveIssue(octokit, owner, repo, issueNumber, vulnId) {
	const timestamp = (/* @__PURE__ */ new Date()).toISOString();
	await octokit.rest.issues.createComment({
		owner,
		repo,
		issue_number: issueNumber,
		body: `✅ This vulnerability (${vulnId}) is no longer detected in the latest scan.\n\n*Auto-closed on ${timestamp}*`
	});
	await octokit.rest.issues.update({
		owner,
		repo,
		issue_number: issueNumber,
		state: "closed"
	});
}
/**
* Generate markdown report from Trivy results
*/
function generateMarkdownReport(trivyReport) {
	const counts = countBySeverity(trivyReport);
	const total = getTotalCount(counts);
	const timestamp = (/* @__PURE__ */ new Date()).toISOString();
	let markdown = "# 🔒 Trivy Security Report\n\n";
	markdown += "## 📊 Summary\n\n";
	markdown += "| Severity | Count |\n";
	markdown += "|----------|-------|\n";
	markdown += `| 🔴 CRITICAL | ${counts.CRITICAL} |\n`;
	markdown += `| 🟠 HIGH | ${counts.HIGH} |\n`;
	markdown += `| 🟡 MEDIUM | ${counts.MEDIUM} |\n`;
	markdown += `| 🟢 LOW | ${counts.LOW} |\n`;
	if (counts.UNKNOWN > 0) markdown += `| ⚪ UNKNOWN | ${counts.UNKNOWN} |\n`;
	markdown += `| **📈 Total** | **${total}** |\n\n`;
	for (const result of trivyReport.Results) {
		if (!result.Vulnerabilities || result.Vulnerabilities.length === 0) continue;
		markdown += "---\n\n";
		markdown += `## 📦 Target: ${result.Target}\n\n`;
		markdown += `**Type:** ${result.Type || "N/A"} | **Class:** ${result.Class || "N/A"}\n\n`;
		const grouped = groupBySeverity(result.Vulnerabilities);
		for (const [severity, vulns] of grouped.entries()) {
			if (vulns.length === 0) continue;
			const emoji = {
				CRITICAL: "🔴",
				HIGH: "🟠",
				MEDIUM: "🟡",
				LOW: "🟢",
				UNKNOWN: "⚪"
			}[severity] || "⚪";
			markdown += `### ${emoji} ${severity} (${vulns.length})\n`;
			markdown += generateVulnerabilityTable(vulns);
			markdown += "\n";
		}
	}
	markdown += "---\n\n";
	markdown += `*Report generated on: ${timestamp}*\n\n`;
	markdown += "*Powered by [Trivy](https://trivy.dev/)*\n";
	if (markdown.length > MAX_ISSUE_BODY_SIZE) markdown = markdown.substring(0, MAX_ISSUE_BODY_SIZE - 133) + "\n\n---\n\n⚠️ **Note:** This report was truncated due to size limitations. Please check the full Trivy report file for complete details.\n";
	return markdown;
}
/**
* Search for an existing issue with the given title
*/
async function findExistingIssue(octokit, owner, repo, issueTitle) {
	try {
		const { data: issues } = await octokit.rest.issues.listForRepo({
			owner,
			repo,
			state: "open",
			creator: "github-actions[bot]",
			per_page: 100
		});
		const existingIssue = issues.find((issue) => issue.title === issueTitle);
		return existingIssue ? existingIssue.number : null;
	} catch (error) {
		console.warn("Failed to search for existing issues:", error);
		return null;
	}
}
/**
* Function that creates or updates GitHub issues based on a Trivy report.
* @param octokit The Octokit GitHub instance.
* @param owner Repository owner
* @param repo Repository name
* @param trivyReport The parsed Trivy report
* @param issueTitle The title for the issue (only used in single mode)
* @param labels Optional labels to apply
* @param issueMode Mode for issue creation: 'single' or 'per-cve'
* @returns Issue result or array of issue results
*/
async function createOrUpdateIssue(octokit, owner, repo, trivyReport, issueTitle, labels, issueMode = "single") {
	if (issueMode === "per-cve") return await handlePerCveMode(octokit, owner, repo, trivyReport, labels || []);
	return await handleSingleMode(octokit, owner, repo, trivyReport, issueTitle, labels);
}
/**
* Handle per-CVE issue mode
*/
async function handlePerCveMode(octokit, owner, repo, trivyReport, labels) {
	const results = [];
	const aggregated = aggregateVulnerabilities(trivyReport);
	const currentVulnIds = new Set(aggregated.keys());
	for (const vuln of aggregated.values()) {
		const result = await createOrUpdateCveIssue(octokit, owner, repo, vuln, labels);
		results.push(result);
	}
	try {
		const { data: issues } = await octokit.rest.issues.listForRepo({
			owner,
			repo,
			state: "open",
			creator: "github-actions[bot]",
			per_page: 100
		});
		for (const issue of issues) {
			const match = issue.title.match(/^\[Security\] ([A-Z]+-\d+-\d+):/);
			if (match) {
				const vulnId = match[1];
				if (!currentVulnIds.has(vulnId)) {
					await closeCveIssue(octokit, owner, repo, issue.number, vulnId);
					results.push({
						issueNumber: issue.number,
						issueUrl: issue.html_url,
						vulnerabilitiesFound: false
					});
				}
			}
		}
	} catch (error) {
		console.warn("Failed to check for resolved vulnerabilities:", error);
	}
	return results;
}
/**
* Handle single issue mode (original behavior)
*/
async function handleSingleMode(octokit, owner, repo, trivyReport, issueTitle, labels) {
	const totalVulns = getTotalCount(countBySeverity(trivyReport));
	const existingIssueNumber = await findExistingIssue(octokit, owner, repo, issueTitle);
	if (totalVulns === 0) {
		if (existingIssueNumber) {
			await octokit.rest.issues.update({
				owner,
				repo,
				issue_number: existingIssueNumber,
				state: "closed"
			});
			return {
				issueNumber: existingIssueNumber,
				issueUrl: `https://github.com/${owner}/${repo}/issues/${existingIssueNumber}`,
				vulnerabilitiesFound: false
			};
		}
		return {
			issueNumber: void 0,
			issueUrl: void 0,
			vulnerabilitiesFound: false
		};
	}
	const markdownBody = generateMarkdownReport(trivyReport);
	if (existingIssueNumber) {
		await octokit.rest.issues.update({
			owner,
			repo,
			issue_number: existingIssueNumber,
			body: markdownBody,
			labels: labels && labels.length > 0 ? labels : void 0
		});
		const timestamp = (/* @__PURE__ */ new Date()).toISOString();
		await octokit.rest.issues.createComment({
			owner,
			repo,
			issue_number: existingIssueNumber,
			body: `🔄 Report updated on ${timestamp}`
		});
		return {
			issueNumber: existingIssueNumber,
			issueUrl: `https://github.com/${owner}/${repo}/issues/${existingIssueNumber}`,
			vulnerabilitiesFound: true
		};
	}
	const { data: newIssue } = await octokit.rest.issues.create({
		owner,
		repo,
		title: issueTitle,
		body: markdownBody,
		labels: labels && labels.length > 0 ? labels : void 0
	});
	return {
		issueNumber: newIssue.number,
		issueUrl: newIssue.html_url,
		vulnerabilitiesFound: true
	};
}

//#endregion
//#region src/main.ts
/**
* The main function for the action.
* @returns {Promise<void>} Resolves when the action is complete.
*/
async function run() {
	try {
		const reportPath = core.getInput("report-path", { required: true });
		const issueTitle = core.getInput("issue-title", { required: true });
		const githubToken = core.getInput("github-token", { required: true });
		const labelsInput = core.getInput("labels", { required: false });
		const issueModeInput = core.getInput("issue-mode", { required: false });
		const labels = labelsInput ? labelsInput.split(",").map((l) => l.trim()).filter((l) => l.length > 0) : [];
		const issueMode = issueModeInput === "per-cve" ? "per-cve" : "single";
		if (issueModeInput && issueModeInput !== "single" && issueModeInput !== "per-cve") core.warning(`Invalid issue-mode '${issueModeInput}'. Using default 'single' mode.`);
		const octokit = getOctokit(githubToken);
		const { owner, repo } = context.repo;
		core.info(`📄 Parsing Trivy report from: ${reportPath}`);
		const result = await createOrUpdateIssue(octokit, owner, repo, await parseTrivyReport(reportPath), issueTitle, labels, issueMode);
		if (Array.isArray(result)) {
			const createdOrUpdated = result.filter((r) => r.vulnerabilitiesFound);
			const closed = result.filter((r) => !r.vulnerabilitiesFound);
			if (createdOrUpdated.length > 0) {
				core.info(`✅ Created or updated ${createdOrUpdated.length} issue(s) for vulnerabilities`);
				for (const r of createdOrUpdated) core.info(`   - Issue #${r.issueNumber}: ${r.issueUrl}`);
				core.setOutput("issue-url", createdOrUpdated[0].issueUrl);
			}
			if (closed.length > 0) core.info(`🔒 Closed ${closed.length} resolved vulnerability issue(s)`);
			if (createdOrUpdated.length === 0 && closed.length === 0) core.info("✅ No vulnerabilities found");
		} else if (result.vulnerabilitiesFound) {
			core.setOutput("issue-url", result.issueUrl);
			core.info(`✅ Issue #${result.issueNumber} updated successfully`);
			core.info(`🔗 ${result.issueUrl}`);
		} else core.info("✅ No vulnerabilities found");
	} catch (error) {
		if (error instanceof Error) core.setFailed(`❌ Action failed: ${error.message}`);
		else core.setFailed("❌ An unknown error occurred");
	}
}

//#endregion
//#region src/index.ts
/**
* The entrypoint for the action.
*/
run();

//#endregion
export {  };
//# sourceMappingURL=index.mjs.map