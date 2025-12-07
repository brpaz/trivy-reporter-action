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
* Function that creates or updates a GitHub issue based on a Trivy report.
* @param octokit The Octokit GitHub instance.
* @param owner Repository owner
* @param repo Repository name
* @param trivyReport The parsed Trivy report
* @param issueTitle The title for the issue
* @param labels Optional labels to apply
* @returns Issue number and URL
*/
async function createOrUpdateIssue(octokit, owner, repo, trivyReport, issueTitle, labels) {
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
		const labels = labelsInput ? labelsInput.split(",").map((l) => l.trim()).filter((l) => l.length > 0) : [];
		const octokit = getOctokit(githubToken);
		const { owner, repo } = context.repo;
		core.info(`📄 Parsing Trivy report from: ${reportPath}`);
		const { issueNumber, issueUrl, vulnerabilitiesFound } = await createOrUpdateIssue(octokit, owner, repo, await parseTrivyReport(reportPath), issueTitle, labels);
		if (vulnerabilitiesFound) {
			core.setOutput("issue-url", issueUrl);
			core.info(`✅ Issue #${issueNumber} updated successfully`);
			core.info(`🔗 ${issueUrl}`);
		}
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