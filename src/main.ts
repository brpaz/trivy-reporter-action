import * as core from '@actions/core'
import { getOctokit, context } from '@actions/github'
import { parseTrivyReport } from './trivy.js'
import { createOrUpdateIssue, type IssueMode } from './issue.js'

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
export async function run(): Promise<void> {
  try {
    const reportPath = core.getInput('report-path', { required: true })
    const issueTitle = core.getInput('issue-title', { required: true })
    const githubToken = core.getInput('github-token', { required: true })
    const labelsInput = core.getInput('labels', { required: false })
    const issueModeInput = core.getInput('issue-mode', { required: false })

    const labels = labelsInput
      ? labelsInput
          .split(',')
          .map((l) => l.trim())
          .filter((l) => l.length > 0)
      : []

    // Validate issue mode
    const issueMode: IssueMode =
      issueModeInput === 'per-cve' ? 'per-cve' : 'single'
    if (
      issueModeInput &&
      issueModeInput !== 'single' &&
      issueModeInput !== 'per-cve'
    ) {
      core.warning(
        `Invalid issue-mode '${issueModeInput}'. Using default 'single' mode.`,
      )
    }

    const octokit = getOctokit(githubToken)
    const { owner, repo } = context.repo

    core.info(`📄 Parsing Trivy report from: ${reportPath}`)

    const trivyReport = await parseTrivyReport(reportPath)

    const result = await createOrUpdateIssue(
      octokit,
      owner,
      repo,
      trivyReport,
      issueTitle,
      labels,
      issueMode,
    )

    // Handle output based on mode
    if (Array.isArray(result)) {
      // Per-CVE mode: multiple issues
      const createdOrUpdated = result.filter((r) => r.vulnerabilitiesFound)
      const closed = result.filter((r) => !r.vulnerabilitiesFound)

      if (createdOrUpdated.length > 0) {
        core.info(
          `✅ Created or updated ${createdOrUpdated.length} issue(s) for vulnerabilities`,
        )
        for (const r of createdOrUpdated) {
          core.info(`   - Issue #${r.issueNumber}: ${r.issueUrl}`)
        }
        // Set output to first issue URL (for backward compatibility)
        core.setOutput('issue-url', createdOrUpdated[0].issueUrl)
      }

      if (closed.length > 0) {
        core.info(`🔒 Closed ${closed.length} resolved vulnerability issue(s)`)
      }

      if (createdOrUpdated.length === 0 && closed.length === 0) {
        core.info('✅ No vulnerabilities found')
      }
    } else {
      // Single mode: one issue
      if (result.vulnerabilitiesFound) {
        core.setOutput('issue-url', result.issueUrl)
        core.info(`✅ Issue #${result.issueNumber} updated successfully`)
        core.info(`🔗 ${result.issueUrl}`)
      } else {
        core.info('✅ No vulnerabilities found')
      }
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`❌ Action failed: ${error.message}`)
    } else {
      core.setFailed('❌ An unknown error occurred')
    }
  }
}
