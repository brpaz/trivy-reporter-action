import { type TrivyReport, type TrivyVulnerability } from './trivy.js'
import { GitHub } from '@actions/github/lib/utils.js'

// GitHub issue body size limit (leaving some buffer)
const MAX_ISSUE_BODY_SIZE = 60000

interface SeverityCounts {
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  UNKNOWN: number
}

/**
 * Count vulnerabilities by severity
 */
function countBySeverity(report: TrivyReport): SeverityCounts {
  const counts: SeverityCounts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  }

  for (const result of report.Results) {
    if (!result.Vulnerabilities) continue

    for (const vuln of result.Vulnerabilities) {
      const severity = vuln.Severity?.toUpperCase() || 'UNKNOWN'
      if (severity in counts) {
        counts[severity as keyof SeverityCounts]++
      } else {
        counts.UNKNOWN++
      }
    }
  }

  return counts
}

/**
 * Get total vulnerability count
 */
function getTotalCount(counts: SeverityCounts): number {
  return (
    counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW + counts.UNKNOWN
  )
}

/**
 * Group vulnerabilities by severity
 */
function groupBySeverity(
  vulnerabilities: TrivyVulnerability[],
): Map<string, TrivyVulnerability[]> {
  const groups = new Map<string, TrivyVulnerability[]>()
  const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']

  // Initialize groups in order
  for (const severity of severityOrder) {
    groups.set(severity, [])
  }

  // Group vulnerabilities
  for (const vuln of vulnerabilities) {
    const severity = vuln.Severity?.toUpperCase() || 'UNKNOWN'
    const group = groups.get(severity)
    if (group) {
      group.push(vuln)
    } else {
      // If severity not in our list, add to UNKNOWN
      groups.get('UNKNOWN')!.push(vuln)
    }
  }

  return groups
}

/**
 * Truncate text to specified length with ellipsis
 */
function truncateText(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) return text || 'N/A'
  return text.substring(0, maxLength) + '...'
}

/**
 * Generate markdown table for vulnerabilities of a specific severity
 */
function generateVulnerabilityTable(
  vulnerabilities: TrivyVulnerability[],
): string {
  if (vulnerabilities.length === 0) return ''

  let table =
    '\n| Package | Vulnerability ID | Installed Version | Fixed Version | Description |\n'
  table +=
    '|---------|------------------|-------------------|---------------|-------------|\n'

  for (const vuln of vulnerabilities) {
    const vulnId = vuln.PrimaryURL
      ? `[${vuln.VulnerabilityID}](${vuln.PrimaryURL})`
      : vuln.VulnerabilityID
    const pkgName = vuln.PkgName || 'N/A'
    const installedVersion = vuln.InstalledVersion || 'N/A'
    const fixedVersion = vuln.FixedVersion || 'Not Available'
    const description = truncateText(
      vuln.Description || vuln.Title || 'No description available',
      100,
    )

    table += `| ${pkgName} | ${vulnId} | ${installedVersion} | ${fixedVersion} | ${description} |\n`
  }

  return table
}

/**
 * Generate markdown report from Trivy results
 */
export function generateMarkdownReport(trivyReport: TrivyReport): string {
  const counts = countBySeverity(trivyReport)
  const total = getTotalCount(counts)
  const timestamp = new Date().toISOString()

  let markdown = '# 🔒 Trivy Security Report\n\n'

  // Summary section
  markdown += '## 📊 Summary\n\n'
  markdown += '| Severity | Count |\n'
  markdown += '|----------|-------|\n'
  markdown += `| 🔴 CRITICAL | ${counts.CRITICAL} |\n`
  markdown += `| 🟠 HIGH | ${counts.HIGH} |\n`
  markdown += `| 🟡 MEDIUM | ${counts.MEDIUM} |\n`
  markdown += `| 🟢 LOW | ${counts.LOW} |\n`
  if (counts.UNKNOWN > 0) {
    markdown += `| ⚪ UNKNOWN | ${counts.UNKNOWN} |\n`
  }
  markdown += `| **📈 Total** | **${total}** |\n\n`

  // Process each target
  for (const result of trivyReport.Results) {
    if (!result.Vulnerabilities || result.Vulnerabilities.length === 0) {
      continue
    }

    markdown += '---\n\n'
    markdown += `## 📦 Target: ${result.Target}\n\n`
    markdown += `**Type:** ${result.Type || 'N/A'} | **Class:** ${result.Class || 'N/A'}\n\n`

    // Group vulnerabilities by severity
    const grouped = groupBySeverity(result.Vulnerabilities)

    // Generate sections for each severity level
    for (const [severity, vulns] of grouped.entries()) {
      if (vulns.length === 0) continue

      const emoji =
        {
          CRITICAL: '🔴',
          HIGH: '🟠',
          MEDIUM: '🟡',
          LOW: '🟢',
          UNKNOWN: '⚪',
        }[severity] || '⚪'

      markdown += `### ${emoji} ${severity} (${vulns.length})\n`
      markdown += generateVulnerabilityTable(vulns)
      markdown += '\n'
    }
  }

  markdown += '---\n\n'
  markdown += `*Report generated on: ${timestamp}*\n\n`
  markdown += '*Powered by [Trivy](https://trivy.dev/)*\n'

  // Truncate if too large
  if (markdown.length > MAX_ISSUE_BODY_SIZE) {
    const truncateMessage =
      '\n\n---\n\n⚠️ **Note:** This report was truncated due to size limitations. Please check the full Trivy report file for complete details.\n'
    markdown =
      markdown.substring(0, MAX_ISSUE_BODY_SIZE - truncateMessage.length) +
      truncateMessage
  }

  return markdown
}

export type IssueResult = {
  issueNumber: number | undefined
  issueUrl: string | undefined
  vulnerabilitiesFound: boolean
}

/**
 * Search for an existing issue with the given title
 */
async function findExistingIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  issueTitle: string,
): Promise<number | null> {
  try {
    const { data: issues } = await octokit.rest.issues.listForRepo({
      owner,
      repo,
      state: 'open',
      creator: 'github-actions[bot]',
      per_page: 100,
    })

    const existingIssue = issues.find((issue) => issue.title === issueTitle)
    return existingIssue ? existingIssue.number : null
  } catch (error) {
    // If we can't search, we'll just create a new issue
    console.warn('Failed to search for existing issues:', error)
    return null
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
export async function createOrUpdateIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  trivyReport: TrivyReport,
  issueTitle: string,
  labels?: string[],
): Promise<IssueResult> {
  // Count total vulnerabilities
  const counts = countBySeverity(trivyReport)
  const totalVulns = getTotalCount(counts)

  // Search for existing issue
  const existingIssueNumber = await findExistingIssue(
    octokit,
    owner,
    repo,
    issueTitle,
  )

  // If no vulnerabilities found, close existing issue if it exists
  if (totalVulns === 0) {
    if (existingIssueNumber) {
      await octokit.rest.issues.update({
        owner,
        repo,
        issue_number: existingIssueNumber,
        state: 'closed',
      })

      const issueUrl = `https://github.com/${owner}/${repo}/issues/${existingIssueNumber}`
      return {
        issueNumber: existingIssueNumber,
        issueUrl,
        vulnerabilitiesFound: false,
      }
    }

    // No existing issue and no vulnerabilities - nothing to do
    return {
      issueNumber: undefined,
      issueUrl: undefined,
      vulnerabilitiesFound: false,
    }
  }

  // Generate markdown report
  const markdownBody = generateMarkdownReport(trivyReport)

  // Update existing issue
  if (existingIssueNumber) {
    await octokit.rest.issues.update({
      owner,
      repo,
      issue_number: existingIssueNumber,
      body: markdownBody,
      labels: labels && labels.length > 0 ? labels : undefined,
    })

    const timestamp = new Date().toISOString()
    await octokit.rest.issues.createComment({
      owner,
      repo,
      issue_number: existingIssueNumber,
      body: `🔄 Report updated on ${timestamp}`,
    })

    const issueUrl = `https://github.com/${owner}/${repo}/issues/${existingIssueNumber}`
    return {
      issueNumber: existingIssueNumber,
      issueUrl,
      vulnerabilitiesFound: true,
    }
  }

  // Create new issue
  const { data: newIssue } = await octokit.rest.issues.create({
    owner,
    repo,
    title: issueTitle,
    body: markdownBody,
    labels: labels && labels.length > 0 ? labels : undefined,
  })

  return {
    issueNumber: newIssue.number,
    issueUrl: newIssue.html_url,
    vulnerabilitiesFound: true,
  }
}
