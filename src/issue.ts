import { type TrivyReport, type TrivyVulnerability } from './trivy.js'
import { GitHub } from '@actions/github/lib/utils.js'

// GitHub issue body size limit (leaving some buffer)
const MAX_ISSUE_BODY_SIZE = 60000

// GitHub issue title limit
const MAX_ISSUE_TITLE_LENGTH = 256

export type IssueMode = 'single' | 'per-cve'

export interface VulnerabilityOccurrence {
  target: string
  pkgName: string
  installedVersion: string
  fixedVersion: string
  type: string
  class: string
}

export interface AggregatedVulnerability {
  vulnerabilityId: string
  severity: string
  title: string
  description: string
  references: string[]
  primaryUrl?: string
  cweIds?: string[]
  publishedDate?: string
  lastModifiedDate?: string
  occurrences: VulnerabilityOccurrence[]
}

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
 * Aggregate vulnerabilities by VulnerabilityID across all results
 */
export function aggregateVulnerabilities(
  trivyReport: TrivyReport,
): Map<string, AggregatedVulnerability> {
  const aggregated = new Map<string, AggregatedVulnerability>()

  for (const result of trivyReport.Results) {
    if (!result.Vulnerabilities) continue

    for (const vuln of result.Vulnerabilities) {
      const vulnId = vuln.VulnerabilityID

      if (!aggregated.has(vulnId)) {
        // First occurrence of this vulnerability
        aggregated.set(vulnId, {
          vulnerabilityId: vulnId,
          severity: vuln.Severity || 'UNKNOWN',
          title: vuln.Title || '',
          description: vuln.Description || '',
          references: vuln.References || [],
          primaryUrl: vuln.PrimaryURL,
          cweIds: vuln.CweIDs,
          publishedDate: vuln.PublishedDate,
          lastModifiedDate: vuln.LastModifiedDate,
          occurrences: [],
        })
      }

      // Add this occurrence
      const agg = aggregated.get(vulnId)!
      agg.occurrences.push({
        target: result.Target,
        pkgName: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion,
        type: result.Type,
        class: result.Class,
      })
    }
  }

  return aggregated
}

/**
 * Search for an existing CVE issue by vulnerability ID
 */
async function findExistingCveIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  vulnId: string,
): Promise<number | null> {
  try {
    const { data: issues } = await octokit.rest.issues.listForRepo({
      owner,
      repo,
      state: 'open',
      creator: 'github-actions[bot]',
      per_page: 100,
    })

    const titlePrefix = `[Security] ${vulnId}:`
    const existingIssue = issues.find((issue) =>
      issue.title.startsWith(titlePrefix),
    )
    return existingIssue ? existingIssue.number : null
  } catch (error) {
    console.warn('Failed to search for existing CVE issues:', error)
    return null
  }
}

/**
 * Generate markdown report for a single CVE
 */
export function generateCveMarkdownReport(
  vuln: AggregatedVulnerability,
): string {
  const timestamp = new Date().toISOString()

  // Get severity emoji
  const severityEmoji =
    {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🟢',
      UNKNOWN: '⚪',
    }[vuln.severity.toUpperCase()] || '⚪'

  let markdown = `# ${severityEmoji} ${vuln.severity.toUpperCase()} Severity\n\n`
  markdown += `## Vulnerability: ${vuln.vulnerabilityId}\n\n`

  // Description
  markdown += '### 📋 Description\n\n'
  markdown += `${vuln.description || 'No description available'}\n\n`

  // Title if different from description
  if (vuln.title && vuln.title !== vuln.description) {
    markdown += `**Title:** ${vuln.title}\n\n`
  }

  // CWE IDs
  if (vuln.cweIds && vuln.cweIds.length > 0) {
    markdown += `**CWE IDs:** ${vuln.cweIds.join(', ')}\n\n`
  }

  // References
  if (vuln.references && vuln.references.length > 0) {
    markdown += '### 🔗 References\n\n'
    for (const ref of vuln.references.slice(0, 10)) {
      // Limit to 10 references
      markdown += `- ${ref}\n`
    }
    if (vuln.references.length > 10) {
      markdown += `\n*... and ${vuln.references.length - 10} more references*\n`
    }
    markdown += '\n'
  }

  // Affected packages table
  markdown += '### 📦 Affected Packages\n\n'
  markdown +=
    '| Target | Package | Installed Version | Fixed Version | Type | Class |\n'
  markdown +=
    '|--------|---------|-------------------|---------------|------|-------|\n'

  for (const occ of vuln.occurrences) {
    const target = truncateText(occ.target, 40)
    const pkgName = occ.pkgName || 'N/A'
    const installedVersion = occ.installedVersion || 'N/A'
    const fixedVersion = occ.fixedVersion || 'Not Available'
    const type = occ.type || 'N/A'
    const classValue = occ.class || 'N/A'

    markdown += `| ${target} | ${pkgName} | ${installedVersion} | ${fixedVersion} | ${type} | ${classValue} |\n`
  }

  markdown += '\n'

  // Metadata
  markdown += '---\n\n'
  if (vuln.publishedDate) {
    markdown += `**Published:** ${vuln.publishedDate}\n\n`
  }
  if (vuln.lastModifiedDate) {
    markdown += `**Last Modified:** ${vuln.lastModifiedDate}\n\n`
  }
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

/**
 * Create issue title for a CVE
 */
function createCveIssueTitle(vuln: AggregatedVulnerability): string {
  const prefix = `[Security] ${vuln.vulnerabilityId}:`
  const titleText = vuln.title || vuln.description || 'Security vulnerability'

  // Calculate remaining space for title
  const remainingSpace = MAX_ISSUE_TITLE_LENGTH - prefix.length - 1 // -1 for space

  if (titleText.length <= remainingSpace) {
    return `${prefix} ${titleText}`
  }

  // Truncate title to fit
  return `${prefix} ${titleText.substring(0, remainingSpace - 3)}...`
}

/**
 * Create or update a single CVE issue
 */
async function createOrUpdateCveIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  vuln: AggregatedVulnerability,
  labels: string[],
): Promise<IssueResult> {
  const issueTitle = createCveIssueTitle(vuln)
  const markdownBody = generateCveMarkdownReport(vuln)

  // Search for existing issue
  const existingIssueNumber = await findExistingCveIssue(
    octokit,
    owner,
    repo,
    vuln.vulnerabilityId,
  )

  // Update existing issue
  if (existingIssueNumber) {
    await octokit.rest.issues.update({
      owner,
      repo,
      issue_number: existingIssueNumber,
      title: issueTitle,
      body: markdownBody,
      labels: labels.length > 0 ? labels : undefined,
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
    labels: labels.length > 0 ? labels : undefined,
  })

  return {
    issueNumber: newIssue.number,
    issueUrl: newIssue.html_url,
    vulnerabilitiesFound: true,
  }
}

/**
 * Close a CVE issue that no longer has vulnerabilities
 */
async function closeCveIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  issueNumber: number,
  vulnId: string,
): Promise<void> {
  const timestamp = new Date().toISOString()
  await octokit.rest.issues.createComment({
    owner,
    repo,
    issue_number: issueNumber,
    body: `✅ This vulnerability (${vulnId}) is no longer detected in the latest scan.\n\n*Auto-closed on ${timestamp}*`,
  })

  await octokit.rest.issues.update({
    owner,
    repo,
    issue_number: issueNumber,
    state: 'closed',
  })
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
export async function createOrUpdateIssue(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  trivyReport: TrivyReport,
  issueTitle: string,
  labels?: string[],
  issueMode: IssueMode = 'single',
): Promise<IssueResult | IssueResult[]> {
  // Handle per-cve mode
  if (issueMode === 'per-cve') {
    return await handlePerCveMode(
      octokit,
      owner,
      repo,
      trivyReport,
      labels || [],
    )
  }

  // Handle single mode (original behavior)
  return await handleSingleMode(
    octokit,
    owner,
    repo,
    trivyReport,
    issueTitle,
    labels,
  )
}

/**
 * Handle per-CVE issue mode
 */
async function handlePerCveMode(
  octokit: InstanceType<typeof GitHub>,
  owner: string,
  repo: string,
  trivyReport: TrivyReport,
  labels: string[],
): Promise<IssueResult[]> {
  const results: IssueResult[] = []

  // Aggregate vulnerabilities by ID
  const aggregated = aggregateVulnerabilities(trivyReport)

  // Track current vulnerability IDs
  const currentVulnIds = new Set(aggregated.keys())

  // Create or update issues for each vulnerability
  for (const vuln of aggregated.values()) {
    const result = await createOrUpdateCveIssue(
      octokit,
      owner,
      repo,
      vuln,
      labels,
    )
    results.push(result)
  }

  // Find and close issues for resolved vulnerabilities
  try {
    const { data: issues } = await octokit.rest.issues.listForRepo({
      owner,
      repo,
      state: 'open',
      creator: 'github-actions[bot]',
      per_page: 100,
    })

    for (const issue of issues) {
      // Check if this is a CVE issue
      const match = issue.title.match(/^\[Security\] ([A-Z]+-\d+-\d+):/)
      if (match) {
        const vulnId = match[1]
        // If this vulnerability is not in the current scan, close it
        if (!currentVulnIds.has(vulnId)) {
          await closeCveIssue(octokit, owner, repo, issue.number, vulnId)
          results.push({
            issueNumber: issue.number,
            issueUrl: issue.html_url,
            vulnerabilitiesFound: false,
          })
        }
      }
    }
  } catch (error) {
    console.warn('Failed to check for resolved vulnerabilities:', error)
  }

  return results
}

/**
 * Handle single issue mode (original behavior)
 */
async function handleSingleMode(
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
