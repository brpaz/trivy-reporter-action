import { describe, it, expect, vi, beforeEach } from 'vitest'
import {
  createOrUpdateIssue,
  generateMarkdownReport,
  aggregateVulnerabilities,
  generateCveMarkdownReport,
} from './issue.js'
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
      undefined,
      'single',
    )

    expect(result).not.toBeInstanceOf(Array)
    if (!Array.isArray(result)) {
      expect(result.issueNumber).toBe(42)
      expect(result.issueUrl).toBe('https://github.com/owner/repo/issues/42')
      expect(result.vulnerabilitiesFound).toBe(true)
    }
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
      undefined,
      'single',
    )

    expect(result).not.toBeInstanceOf(Array)
    if (!Array.isArray(result)) {
      expect(result.vulnerabilitiesFound).toBe(false)
      expect(result.issueNumber).toBe(42)
      expect(result.issueUrl).toBe('https://github.com/owner/repo/issues/42')
    }
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
      undefined,
      'single',
    )

    expect(result).not.toBeInstanceOf(Array)
    if (!Array.isArray(result)) {
      expect(result.vulnerabilitiesFound).toBe(false)
      expect(result.issueNumber).toBeUndefined()
      expect(result.issueUrl).toBeUndefined()
    }
    expect(mockOctokit.rest.issues.create).not.toHaveBeenCalled()
    expect(mockOctokit.rest.issues.update).not.toHaveBeenCalled()
    expect(mockOctokit.rest.issues.createComment).not.toHaveBeenCalled()
  })
})

describe('aggregateVulnerabilities', () => {
  it('should aggregate vulnerabilities by ID', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'busybox',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test Vulnerability',
              Description: 'Test description',
              References: ['https://example.com'],
            },
            {
              VulnerabilityID: 'CVE-2024-5678',
              PkgName: 'openssl',
              InstalledVersion: '2.0.0',
              FixedVersion: '2.0.1',
              Severity: 'CRITICAL',
              Title: 'Critical bug',
              Description: 'Critical description',
              References: [],
            },
          ],
        },
        {
          Target: 'node:20',
          Class: 'lang-pkgs',
          Type: 'npm',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'lodash',
              InstalledVersion: '4.17.0',
              FixedVersion: '4.17.21',
              Severity: 'HIGH',
              Title: 'Test Vulnerability',
              Description: 'Test description',
              References: ['https://example.com'],
            },
          ],
        },
      ],
    }

    const aggregated = aggregateVulnerabilities(report)

    expect(aggregated.size).toBe(2)
    expect(aggregated.has('CVE-2024-1234')).toBe(true)
    expect(aggregated.has('CVE-2024-5678')).toBe(true)

    const cve1234 = aggregated.get('CVE-2024-1234')!
    expect(cve1234.vulnerabilityId).toBe('CVE-2024-1234')
    expect(cve1234.severity).toBe('HIGH')
    expect(cve1234.occurrences).toHaveLength(2)
    expect(cve1234.occurrences[0].pkgName).toBe('busybox')
    expect(cve1234.occurrences[0].target).toBe('alpine:3.22.2')
    expect(cve1234.occurrences[1].pkgName).toBe('lodash')
    expect(cve1234.occurrences[1].target).toBe('node:20')

    const cve5678 = aggregated.get('CVE-2024-5678')!
    expect(cve5678.vulnerabilityId).toBe('CVE-2024-5678')
    expect(cve5678.severity).toBe('CRITICAL')
    expect(cve5678.occurrences).toHaveLength(1)
    expect(cve5678.occurrences[0].pkgName).toBe('openssl')
  })

  it('should handle empty results', () => {
    const report: TrivyReport = {
      Results: [],
    }

    const aggregated = aggregateVulnerabilities(report)
    expect(aggregated.size).toBe(0)
  })

  it('should handle results with no vulnerabilities', () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [],
        },
      ],
    }

    const aggregated = aggregateVulnerabilities(report)
    expect(aggregated.size).toBe(0)
  })
})

describe('generateCveMarkdownReport', () => {
  it('should generate report for a single CVE', () => {
    const vuln = {
      vulnerabilityId: 'CVE-2024-1234',
      severity: 'HIGH',
      title: 'Test Vulnerability',
      description: 'This is a test vulnerability description',
      references: ['https://example.com/ref1', 'https://example.com/ref2'],
      primaryUrl: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234',
      cweIds: ['CWE-79', 'CWE-89'],
      publishedDate: '2024-01-01T00:00:00Z',
      lastModifiedDate: '2024-01-02T00:00:00Z',
      occurrences: [
        {
          target: 'alpine:3.22.2',
          pkgName: 'busybox',
          installedVersion: '1.0.0',
          fixedVersion: '1.0.1',
          type: 'alpine',
          class: 'os-pkgs',
        },
        {
          target: 'node:20',
          pkgName: 'lodash',
          installedVersion: '4.17.0',
          fixedVersion: '4.17.21',
          type: 'npm',
          class: 'lang-pkgs',
        },
      ],
    }

    const markdown = generateCveMarkdownReport(vuln)

    expect(markdown).toContain('# 🟠 HIGH Severity')
    expect(markdown).toContain('## Vulnerability: CVE-2024-1234')
    expect(markdown).toContain('This is a test vulnerability description')
    expect(markdown).toContain('**CWE IDs:** CWE-79, CWE-89')
    expect(markdown).toContain('### 🔗 References')
    expect(markdown).toContain('https://example.com/ref1')
    expect(markdown).toContain('### 📦 Affected Packages')
    expect(markdown).toContain('busybox')
    expect(markdown).toContain('lodash')
    expect(markdown).toContain('**Published:** 2024-01-01T00:00:00Z')
    expect(markdown).toContain('**Last Modified:** 2024-01-02T00:00:00Z')
  })

  it('should handle vulnerability with minimal data', () => {
    const vuln = {
      vulnerabilityId: 'CVE-2024-9999',
      severity: 'UNKNOWN',
      title: '',
      description: '',
      references: [],
      occurrences: [
        {
          target: 'test:latest',
          pkgName: 'test-pkg',
          installedVersion: '1.0.0',
          fixedVersion: '',
          type: 'test',
          class: 'test',
        },
      ],
    }

    const markdown = generateCveMarkdownReport(vuln)

    expect(markdown).toContain('CVE-2024-9999')
    expect(markdown).toContain('No description available')
    expect(markdown).toContain('test-pkg')
  })
})

describe('createOrUpdateIssue - per-cve mode', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should create separate issues for each CVE', async () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'busybox',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test Vulnerability 1',
              Description: 'Test description 1',
              References: [],
            },
            {
              VulnerabilityID: 'CVE-2024-5678',
              PkgName: 'openssl',
              InstalledVersion: '2.0.0',
              FixedVersion: '2.0.1',
              Severity: 'CRITICAL',
              Title: 'Test Vulnerability 2',
              Description: 'Test description 2',
              References: [],
            },
          ],
        },
      ],
    }

    mockOctokit.rest.issues.listForRepo.mockResolvedValue({ data: [] })
    mockOctokit.rest.issues.create
      .mockResolvedValueOnce({
        data: {
          number: 1,
          html_url: 'https://github.com/owner/repo/issues/1',
        },
      })
      .mockResolvedValueOnce({
        data: {
          number: 2,
          html_url: 'https://github.com/owner/repo/issues/2',
        },
      })

    const result = await createOrUpdateIssue(
      mockOctokit as any,
      'owner',
      'repo',
      report,
      'Ignored in per-cve mode',
      [],
      'per-cve',
    )

    expect(Array.isArray(result)).toBe(true)
    if (Array.isArray(result)) {
      expect(result).toHaveLength(2)
      expect(result[0].vulnerabilitiesFound).toBe(true)
      expect(result[1].vulnerabilitiesFound).toBe(true)
    }
    expect(mockOctokit.rest.issues.create).toHaveBeenCalledTimes(2)
    expect(mockOctokit.rest.issues.create).toHaveBeenCalledWith(
      expect.objectContaining({
        title: expect.stringContaining('[Security] CVE-2024-1234:'),
      }),
    )
    expect(mockOctokit.rest.issues.create).toHaveBeenCalledWith(
      expect.objectContaining({
        title: expect.stringContaining('[Security] CVE-2024-5678:'),
      }),
    )
  })

  it('should close resolved CVE issues', async () => {
    const report: TrivyReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-1234',
              PkgName: 'busybox',
              InstalledVersion: '1.0.0',
              FixedVersion: '1.0.1',
              Severity: 'HIGH',
              Title: 'Test Vulnerability',
              Description: 'Test description',
              References: [],
            },
          ],
        },
      ],
    }

    // Mock existing issues - one current, one resolved
    mockOctokit.rest.issues.listForRepo.mockResolvedValue({
      data: [
        {
          number: 1,
          title: '[Security] CVE-2024-1234: Test Vulnerability',
          html_url: 'https://github.com/owner/repo/issues/1',
        },
        {
          number: 2,
          title: '[Security] CVE-2024-9999: Old Vulnerability',
          html_url: 'https://github.com/owner/repo/issues/2',
        },
      ],
    })
    mockOctokit.rest.issues.update.mockResolvedValue({ data: {} })
    mockOctokit.rest.issues.createComment.mockResolvedValue({ data: {} })

    const result = await createOrUpdateIssue(
      mockOctokit as any,
      'owner',
      'repo',
      report,
      'Ignored',
      [],
      'per-cve',
    )

    expect(Array.isArray(result)).toBe(true)
    if (Array.isArray(result)) {
      // One updated + one closed
      expect(result.length).toBeGreaterThanOrEqual(2)
      const closed = result.find((r) => !r.vulnerabilitiesFound)
      expect(closed).toBeDefined()
    }

    // Should close the resolved CVE
    expect(mockOctokit.rest.issues.update).toHaveBeenCalledWith(
      expect.objectContaining({
        issue_number: 2,
        state: 'closed',
      }),
    )
  })
})
