import { describe, it, expect, vi, beforeEach } from 'vitest'
import { parseTrivyReport } from './trivy.js'
import * as fs from 'fs/promises'

// Mock fs/promises
vi.mock('fs/promises')

describe('parseTrivyReport', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should successfully parse a valid Trivy JSON report', async () => {
    const mockReport = {
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
              References: ['https://example.com'],
            },
          ],
        },
      ],
    }

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    const result = await parseTrivyReport('/path/to/report.json')

    expect(result).toEqual(mockReport)
    expect(fs.readFile).toHaveBeenCalledWith('/path/to/report.json', 'utf-8')
  })

  it('should handle empty Results array', async () => {
    const mockReport = {
      Results: [],
    }

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    const result = await parseTrivyReport('/path/to/report.json')

    expect(result).toEqual(mockReport)
    expect(result.Results).toHaveLength(0)
  })

  it('should throw error when file is not found', async () => {
    const error: NodeJS.ErrnoException = new Error('File not found')
    error.code = 'ENOENT'
    vi.mocked(fs.readFile).mockRejectedValue(error)

    await expect(parseTrivyReport('/nonexistent/report.json')).rejects.toThrow(
      'Trivy report file not found: /nonexistent/report.json',
    )
  })

  it('should throw error when JSON is invalid', async () => {
    vi.mocked(fs.readFile).mockResolvedValue('{ invalid json }')

    await expect(parseTrivyReport('/path/to/report.json')).rejects.toThrow(
      'Invalid JSON in Trivy report file: /path/to/report.json',
    )
  })

  it('should throw error when Results field is missing', async () => {
    const mockReport = {
      SomeOtherField: 'value',
    }

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    await expect(parseTrivyReport('/path/to/report.json')).rejects.toThrow(
      'Invalid Trivy report: missing Results field',
    )
  })

  it('should throw error when Results is not an array', async () => {
    const mockReport = {
      Results: 'not-an-array',
    }

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    await expect(parseTrivyReport('/path/to/report.json')).rejects.toThrow(
      'Invalid Trivy report: Results must be an array',
    )
  })

  it('should handle Results with no Vulnerabilities', async () => {
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

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    const result = await parseTrivyReport('/path/to/report.json')

    expect(result).toEqual(mockReport)
    expect(result.Results[0].Vulnerabilities).toHaveLength(0)
  })

  it('should handle multiple targets in Results', async () => {
    const mockReport = {
      Results: [
        {
          Target: 'alpine:3.22.2',
          Class: 'os-pkgs',
          Type: 'alpine',
          Vulnerabilities: [],
        },
        {
          Target: 'Node.js',
          Class: 'lang-pkgs',
          Type: 'node-pkg',
          Vulnerabilities: [],
        },
      ],
    }

    vi.mocked(fs.readFile).mockResolvedValue(JSON.stringify(mockReport))

    const result = await parseTrivyReport('/path/to/report.json')

    expect(result.Results).toHaveLength(2)
    expect(result.Results[0].Target).toBe('alpine:3.22.2')
    expect(result.Results[1].Target).toBe('Node.js')
  })
})
