import * as fs from 'fs/promises'

export interface TrivyReport {
  Results: TrivyResult[]
}

export interface TrivyResult {
  Target: string
  Class: string
  Type: string
  Vulnerabilities: TrivyVulnerability[]
}

export interface TrivyVulnerability {
  VulnerabilityID: string
  PkgName: string
  InstalledVersion: string
  FixedVersion: string
  Severity: string
  Title: string
  Description: string
  References: string[]
  PrimaryURL?: string
}

/**
 * This function is responsible for parsing the Trivy report and return a structure with it´s output.
 */
export async function parseTrivyReport(
  reportPath: string,
): Promise<TrivyReport> {
  try {
    // Read the file contents
    const fileContents = await fs.readFile(reportPath, 'utf-8')

    // Parse the JSON
    const report = JSON.parse(fileContents) as TrivyReport

    // Validate that Results field exists
    if (!report.Results) {
      throw new Error('Invalid Trivy report: missing Results field')
    }

    // Ensure Results is an array (even if empty)
    if (!Array.isArray(report.Results)) {
      throw new Error('Invalid Trivy report: Results must be an array')
    }

    return report
  } catch (error) {
    if (error instanceof Error) {
      // Handle specific error types
      if ('code' in error && error.code === 'ENOENT') {
        throw new Error(`Trivy report file not found: ${reportPath}`)
      }
      if (error.name === 'SyntaxError') {
        throw new Error(`Invalid JSON in Trivy report file: ${reportPath}`)
      }
      // Re-throw other errors with context
      throw new Error(`Failed to parse Trivy report: ${error.message}`)
    }
    throw error
  }
}
