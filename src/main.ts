import * as core from '@actions/core'
import { getOctokit, context } from '@actions/github'
import { parseTrivyReport } from './trivy.js'
import { createOrUpdateIssue } from './issue.js'

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

    const labels = labelsInput
      ? labelsInput
          .split(',')
          .map((l) => l.trim())
          .filter((l) => l.length > 0)
      : []

    const octokit = getOctokit(githubToken)
    const { owner, repo } = context.repo

    core.info(`📄 Parsing Trivy report from: ${reportPath}`)

    const trivyReport = await parseTrivyReport(reportPath)

    const { issueNumber, issueUrl, vulnerabilitiesFound } =
      await createOrUpdateIssue(
        octokit,
        owner,
        repo,
        trivyReport,
        issueTitle,
        labels,
      )

    // 5. Set outputs
    if (vulnerabilitiesFound) {
      core.setOutput('issue-url', issueUrl)
      core.info(`✅ Issue #${issueNumber} updated successfully`)
      core.info(`🔗 ${issueUrl}`)
    }
  } catch (error) {
    if (error instanceof Error) {
      core.setFailed(`❌ Action failed: ${error.message}`)
    } else {
      core.setFailed('❌ An unknown error occurred')
    }
  }
}
