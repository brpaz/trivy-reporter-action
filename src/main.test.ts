import { describe, it, expect, vi, beforeEach } from 'vitest'
import { run } from './main.js'
import * as core from '@actions/core'
import * as github from '@actions/github'
import * as trivyModule from './trivy.js'
import * as issueModule from './issue.js'

/* eslint-disable @typescript-eslint/no-explicit-any */

vi.mock('@actions/core')
vi.mock('@actions/github')
vi.mock('./trivy.js')
vi.mock('./issue.js')

describe('run', () => {
  const mockGetInput = vi.mocked(core.getInput)
  const mockSetOutput = vi.mocked(core.setOutput)
  const mockSetFailed = vi.mocked(core.setFailed)
  const mockInfo = vi.mocked(core.info)
  const mockParseTrivyReport = vi.mocked(trivyModule.parseTrivyReport)
  const mockCreateOrUpdateIssue = vi.mocked(issueModule.createOrUpdateIssue)
  const mockGetOctokit = vi.mocked(github.getOctokit)

  beforeEach(() => {
    vi.clearAllMocks()

    // Setup default context
    vi.mocked(github).context = {
      repo: {
        owner: 'test-owner',
        repo: 'test-repo',
      },
    } as any
  })

  it('should successfully run the action', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: 'security,trivy',
      }
      return inputs[name] || ''
    })

    const mockReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [],
        },
      ],
    }

    mockParseTrivyReport.mockResolvedValue(mockReport)
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: 42,
      issueUrl: 'https://github.com/test-owner/test-repo/issues/42',
      vulnerabilitiesFound: true,
    })

    await run()

    expect(mockGetInput).toHaveBeenCalledWith('report-path', { required: true })
    expect(mockGetInput).toHaveBeenCalledWith('issue-title', { required: true })
    expect(mockGetInput).toHaveBeenCalledWith('github-token', {
      required: true,
    })
    expect(mockGetInput).toHaveBeenCalledWith('labels', { required: false })

    expect(mockParseTrivyReport).toHaveBeenCalledWith('trivy-report.json')
    expect(mockCreateOrUpdateIssue).toHaveBeenCalledWith(
      expect.anything(),
      'test-owner',
      'test-repo',
      mockReport,
      'Security Report',
      ['security', 'trivy'],
    )

    expect(mockSetOutput).toHaveBeenCalledWith(
      'issue-url',
      'https://github.com/test-owner/test-repo/issues/42',
    )
    expect(mockInfo).toHaveBeenCalledWith(
      expect.stringContaining('Issue #42 updated successfully'),
    )
  })

  it('should handle labels correctly when provided', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: 'security, trivy, vulnerability',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: 42,
      issueUrl: 'https://github.com/test-owner/test-repo/issues/42',
      vulnerabilitiesFound: true,
    })

    await run()

    expect(mockCreateOrUpdateIssue).toHaveBeenCalledWith(
      expect.anything(),
      'test-owner',
      'test-repo',
      expect.anything(),
      'Security Report',
      ['security', 'trivy', 'vulnerability'],
    )
  })

  it('should handle empty labels input', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: 42,
      issueUrl: 'https://github.com/test-owner/test-repo/issues/42',
      vulnerabilitiesFound: true,
    })

    await run()

    expect(mockCreateOrUpdateIssue).toHaveBeenCalledWith(
      expect.anything(),
      'test-owner',
      'test-repo',
      expect.anything(),
      'Security Report',
      [],
    )
  })

  it('should handle labels with extra whitespace', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '  security  ,  trivy  ,  ',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: 42,
      issueUrl: 'https://github.com/test-owner/test-repo/issues/42',
      vulnerabilitiesFound: true,
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: 42,
      issueUrl: 'https://github.com/test-owner/test-repo/issues/42',
      vulnerabilitiesFound: true,
    })

    await run()

    expect(mockCreateOrUpdateIssue).toHaveBeenCalledWith(
      expect.anything(),
      'test-owner',
      'test-repo',
      expect.anything(),
      'Security Report',
      ['security', 'trivy'],
    )
  })

  it('should handle file parsing errors', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'nonexistent.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockRejectedValue(new Error('File not found'))

    await run()

    expect(mockSetFailed).toHaveBeenCalledWith(
      '❌ Action failed: File not found',
    )
  })

  it('should handle GitHub API errors', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockRejectedValue(
      new Error('API rate limit exceeded'),
    )

    await run()

    expect(mockSetFailed).toHaveBeenCalledWith(
      '❌ Action failed: API rate limit exceeded',
    )
  })

  it('should handle unknown errors', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockRejectedValue('Some non-Error object')

    await run()

    expect(mockSetFailed).toHaveBeenCalledWith('❌ An unknown error occurred')
  })

  it('should succeed when no vulnerabilities are found', async () => {
    mockGetInput.mockImplementation((name: string) => {
      const inputs: Record<string, string> = {
        'report-path': 'trivy-report.json',
        'issue-title': 'Security Report',
        'github-token': 'fake-token',
        labels: '',
      }
      return inputs[name] || ''
    })

    mockParseTrivyReport.mockResolvedValue({ Results: [] })
    mockGetOctokit.mockReturnValue({} as any)
    mockCreateOrUpdateIssue.mockResolvedValue({
      issueNumber: undefined,
      issueUrl: undefined,
      vulnerabilitiesFound: false,
    })

    await run()

    expect(mockSetFailed).not.toHaveBeenCalled()
    expect(mockSetOutput).not.toHaveBeenCalled()
  })
})
