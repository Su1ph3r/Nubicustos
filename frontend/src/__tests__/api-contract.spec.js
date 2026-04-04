import { describe, it, expect, vi, beforeEach } from 'vitest'
import api from '../services/api'

describe('API Contract Tests', () => {
  let lastFetchUrl = null
  let lastFetchOptions = null

  beforeEach(() => {
    lastFetchUrl = null
    lastFetchOptions = null
    global.fetch = vi.fn(async (url, options = {}) => {
      lastFetchUrl = url
      lastFetchOptions = options
      return {
        ok: true,
        text: async () => JSON.stringify({ items: [], total: 0 }),
        json: async () => ({ items: [], total: 0 }),
        headers: new Headers(),
      }
    })
  })

  // ---- Findings ----

  it('getFindings calls GET /api/findings', async () => {
    await api.getFindings({ severity: 'critical', page: 1 })
    expect(lastFetchUrl).toContain('/api/findings')
    expect(lastFetchUrl).toContain('severity=critical')
    expect(lastFetchUrl).toContain('page=1')
    expect(lastFetchOptions.method).toBeUndefined() // GET is the default
  })

  it('getFindings with no params calls /api/findings without query string', async () => {
    await api.getFindings()
    expect(lastFetchUrl).toBe('/api/findings')
  })

  it('getFinding calls GET /api/findings/{id}', async () => {
    await api.getFinding(42)
    expect(lastFetchUrl).toBe('/api/findings/42')
  })

  it('getSummary calls GET /api/findings/summary', async () => {
    await api.getSummary()
    expect(lastFetchUrl).toBe('/api/findings/summary')
  })

  it('getTrend calls GET /api/findings/trend with days param', async () => {
    await api.getTrend(7)
    expect(lastFetchUrl).toBe('/api/findings/trend?days=7')
  })

  it('getTrend defaults to 30 days', async () => {
    await api.getTrend()
    expect(lastFetchUrl).toBe('/api/findings/trend?days=30')
  })

  it('updateFinding calls PATCH /api/findings/{id}', async () => {
    await api.updateFinding(5, { status: 'resolved' })
    expect(lastFetchUrl).toBe('/api/findings/5')
    expect(lastFetchOptions.method).toBe('PATCH')
    expect(JSON.parse(lastFetchOptions.body)).toEqual({ status: 'resolved' })
  })

  // ---- Scans ----

  it('getScans calls GET /api/scans', async () => {
    await api.getScans({ page: 2, status: 'running' })
    expect(lastFetchUrl).toContain('/api/scans')
    expect(lastFetchUrl).toContain('page=2')
    expect(lastFetchUrl).toContain('status=running')
  })

  it('getScans with no params calls /api/scans without query string', async () => {
    await api.getScans()
    expect(lastFetchUrl).toBe('/api/scans')
  })

  it('getScan calls GET /api/scans/{id}', async () => {
    await api.getScan(10)
    expect(lastFetchUrl).toBe('/api/scans/10')
  })

  it('getScanErrors calls GET /api/scans/{id}/errors', async () => {
    await api.getScanErrors(10)
    expect(lastFetchUrl).toBe('/api/scans/10/errors')
  })

  // ---- Exports (URL builders, no fetch) ----

  it('getExportUrl builds correct CSV URL with params', () => {
    const url = api.getExportUrl('csv', { severity: 'critical', status: 'open' })
    expect(url).toBe('/api/exports/csv?severity=critical&status=open')
  })

  it('getExportUrl builds correct JSON URL without params', () => {
    const url = api.getExportUrl('json')
    expect(url).toBe('/api/exports/json')
  })

  it('getExportUrl includes account_id when provided', () => {
    const url = api.getExportUrl('csv', { account_id: '123456789' })
    expect(url).toBe('/api/exports/csv?account_id=123456789')
  })

  it('getExportUrl includes include_remediation flag', () => {
    const url = api.getExportUrl('json', { include_remediation: true })
    expect(url).toBe('/api/exports/json?include_remediation=true')
  })

  // ---- Health ----

  it('getHealth calls GET /api/health', async () => {
    await api.getHealth()
    expect(lastFetchUrl).toBe('/api/health')
  })

  it('getDetailedHealth calls GET /api/health/detailed', async () => {
    await api.getDetailedHealth()
    expect(lastFetchUrl).toBe('/api/health/detailed')
  })

  // ---- Compliance ----

  it('getComplianceFrameworks calls GET /api/compliance/frameworks', async () => {
    await api.getComplianceFrameworks()
    expect(lastFetchUrl).toBe('/api/compliance/frameworks')
  })

  it('getComplianceSummary calls GET /api/compliance/summary', async () => {
    await api.getComplianceSummary()
    expect(lastFetchUrl).toBe('/api/compliance/summary')
  })

  it('getComplianceFrameworkDetails calls GET /api/compliance/frameworks/{framework}', async () => {
    await api.getComplianceFrameworkDetails('cis-aws')
    expect(lastFetchUrl).toBe('/api/compliance/frameworks/cis-aws')
  })

  it('getComplianceControlDetails calls GET /api/compliance/frameworks/{framework}/controls/{id}', async () => {
    await api.getComplianceControlDetails('cis-aws', 'ctrl-1')
    expect(lastFetchUrl).toBe('/api/compliance/frameworks/cis-aws/controls/ctrl-1')
  })

  it('getComplianceExportUrl builds CSV export URL with framework', () => {
    const url = api.getComplianceExportUrl('cis-aws')
    expect(url).toBe('/api/compliance/export/csv?framework=cis-aws')
  })

  it('getComplianceExportUrl builds CSV export URL without framework', () => {
    const url = api.getComplianceExportUrl()
    expect(url).toBe('/api/compliance/export/csv')
  })

  // ---- IaC Scanning ----

  it('getIaCProfiles calls GET /api/iac/profiles', async () => {
    await api.getIaCProfiles()
    expect(lastFetchUrl).toBe('/api/iac/profiles')
  })

  it('uploadIaCFiles calls POST /api/iac/upload with FormData', async () => {
    const mockFile = new File(['content'], 'main.tf', { type: 'text/plain' })
    await api.uploadIaCFiles([mockFile])
    expect(lastFetchUrl).toBe('/api/iac/upload')
    expect(lastFetchOptions.method).toBe('POST')
    expect(lastFetchOptions.body).toBeInstanceOf(FormData)
  })

  it('startIaCScan calls POST /api/iac/scan/{id}', async () => {
    await api.startIaCScan('scan-123', 'iac-full')
    expect(lastFetchUrl).toBe('/api/iac/scan/scan-123?profile=iac-full')
    expect(lastFetchOptions.method).toBe('POST')
  })

  it('startIaCScan defaults to iac-quick profile', async () => {
    await api.startIaCScan('scan-456')
    expect(lastFetchUrl).toBe('/api/iac/scan/scan-456?profile=iac-quick')
  })

  it('deleteIaCStagingFiles calls DELETE /api/iac/staging/{id}', async () => {
    await api.deleteIaCStagingFiles('scan-789')
    expect(lastFetchUrl).toBe('/api/iac/staging/scan-789')
    expect(lastFetchOptions.method).toBe('DELETE')
  })
})
