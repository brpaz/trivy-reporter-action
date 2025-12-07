import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createOrUpdateIssue, generateMarkdownReport } from './issue.js'
import type { TrivyReport } from './trivy.js'

/* eslint-disable @typescript-eslint/no-explicit-any */

// Mock GitHub client
const mockOctokit = {
  rest: {
    issues: {
      listForRepo: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      createComment: vi.fn(),
    },
  },
}

describe('generateMarkdownReport', () => {
  it('should generate a report with vulnerability summary', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'test-pkg',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test Vulnerability',
              Description: 'Test description',
              References: [],
              PrimaryURL: 'https://example.com/CVE-2024-1234',
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('# 🔒 Trivy Security Report')
    expect(markdown).toContain('## 📊 Summary')
    expect(markdown).toContain('🟠 HIGH | 1')
    expect(markdown).toContain('## 📦 Target: test-image')
    expect(markdown).toContain('CVE-2024-1234')
    expect(markdown).toContain('test-pkg')
  })

  it('should group vulnerabilities by severity', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1',
              PkgName: 'pkg1',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'CRITICAL',
              Title: 'Critical vuln',
              Description: 'Critical description',
              References: [],
            },
            {
              VulnerabilityID: 'CVE-2024-2',
              PkgName: 'pkg2',
              InstalledVersion: '2.0.0',
              FixedVersion: '2.0.1',
              Severity: 'LOW',
              Title: 'Low vuln',
              Description: 'Low description',
              References: [],
            },
            {
              VulnerabilityID: 'CVE-2024-3',
              PkgName: 'pkg3',
              InstalledVersion: '3.0.0',
              FixedVersion: '3.0.1',
              Severity: 'HIGH',
              Title: 'High vuln',
              Description: 'High description',
              References: [],
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('🔴 CRITICAL | 1')
    expect(markdown).toContain('🟠 HIGH | 1')
    expect(markdown).toContain('🟢 LOW | 1')
    expect(markdown).toContain('### 🔴 CRITICAL')
    expect(markdown).toContain('### 🟠 HIGH')
    expect(markdown).toContain('### 🟢 LOW')
  })

  it('should handle multiple targets', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1',
              PkgName: 'pkg1',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test',
              Description: 'Test',
              References: [],
            },
          ],
        },
        {
          Target: 'Node.js',
          Class: 'lang-pkgs',
          Type: 'node-pkg',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-2',
              PkgName: 'pkg2',
              InstalledVersion: '2.0.0',
              FixedVersion: '2.0.1',
              Severity: 'MEDIUM',
              Title: 'Test2',
              Description: 'Test2',
              References: [],
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('## 📦 Target: alpine:3.22.2')
    expect(markdown).toContain('## 📦 Target: Node.js')
    expect(markdown).toContain('**Type:** alpine')
    expect(markdown).toContain('**Type:** node-pkg')
  })

  it('should handle vulnerabilities without FixedVersion', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'test-pkg',
              InstalledVersion: '1.0.0',
              FixedVersion: '',
              Severity: 'HIGH',
              Title: 'Test Vulnerability',
              Description: 'Test description',
              References: [],
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('Not Available')
  })

  it('should truncate long descriptions', () => {
    const longDescription = 'a'.repeat(200)
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'test-pkg',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test',
              Description: longDescription,
              References: [],
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('...')
    expect(markdown).not.toContain(longDescription)
  })

  it('should link vulnerability IDs when PrimaryURL is available', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'test-pkg',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test',
              Description: 'Test',
              References: [],
              PrimaryURL: 'https://avd.aquasec.com/nvd/cve-2024-1234',
            },
          ],
        },
      ],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain(
      '[CVE-2024-1234](https://avd.aquasec.com/nvd/cve-2024-1234)',
    )
  })

  it('should include timestamp and Trivy attribution', () => {
    const report: TrivyReport = {
      Results: [],
    }

    const markdown = generateMarkdownReport(report)

    expect(markdown).toContain('*Report generated on:')
    expect(markdown).toContain('*Powered by [Trivy](https://trivy.dev/)*')
  })
})

describe('createOrUpdateIssue', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should create a new issue when none exists', async () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'test-image',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'test-pkg',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test',
              Description: 'Test',
              References: [],
            },
          ],
        },
      ],
    }

    mockOctokit.rest.issues.listForRepo.mockResolvedValue({ data: [] })
    mockOctokit.rest.issues.create.mockResolvedValue({
      data: { number: 42, html_url: 'https://github.com/owner/repo/issues/42' },
    })

    const result = await createOrUpdateIssue(
      mockOctokit as any,
      'owner',
      'repo',
      report,
      'Security Report',
    )

    expect(result.issueNumber).toBe(42)
    expect(result.issueUrl).toBe('https://github.com/owner/repo/issues/42')
    expect(result.vulnerabilitiesFound).toBe(true)
    expect(mockOctokit.rest.issues.create).toHaveBeenCalledWith(
      expect.objectContaining({
        owner: 'owner',
        repo: 'repo',
        title: 'Security Report',
      }),
    )
  })

  it('should close issue when no vulnerabilities are found', async () => {
    const report: TrivyReport = {
      Results: [],
    }

    mockOctokit.rest.issues.listForRepo.mockResolvedValue({
      data: [{ number: 42, title: 'Security Report' }],
    })
    mockOctokit.rest.issues.update.mockResolvedValue({ data: {} })

    const result = await createOrUpdateIssue(
      mockOctokit as any,
      'owner',
      'repo',
      report,
      'Security Report',
    )

    expect(result.vulnerabilitiesFound).toBe(false)
    expect(result.issueNumber).toBe(42)
    expect(result.issueUrl).toBe('https://github.com/owner/repo/issues/42')
    expect(mockOctokit.rest.issues.update).toHaveBeenCalledWith(
      expect.objectContaining({
        state: 'closed',
      }),
    )
  })

  it('should return vulnerabilitiesFound false when no vulnerabilities and no existing issue', async () => {
    const report: TrivyReport = {
      Results: [],
    }

    mockOctokit.rest.issues.listForRepo.mockResolvedValue({ data: [] })

    const result = await createOrUpdateIssue(
      mockOctokit as any,
      'owner',
      'repo',
      report,
      'Security Report',
    )

    expect(result.vulnerabilitiesFound).toBe(false)
    expect(result.issueNumber).toBeUndefined()
    expect(result.issueUrl).toBeUndefined()
    expect(mockOctokit.rest.issues.create).not.toHaveBeenCalled()
    expect(mockOctokit.rest.issues.update).not.toHaveBeenCalled()
    expect(mockOctokit.rest.issues.createComment).not.toHaveBeenCalled()
  })
})
