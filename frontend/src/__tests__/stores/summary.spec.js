/**
 * Tests for summary store
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useSummaryStore } from '../../stores/summary'

// Mock the API module
vi.mock('../../services/api', () => ({
  default: {
    getSummary: vi.fn(),
  },
}))

import api from '../../services/api'

describe('Summary Store', () => {
  let store

  beforeEach(() => {
    setActivePinia(createPinia())
    store = useSummaryStore()
    vi.clearAllMocks()
  })

  describe('Initial State', () => {
    it('should have null summary', () => {
      expect(store.summary).toBeNull()
    })

    it('should not be loading initially', () => {
      expect(store.loading).toBe(false)
    })

    it('should have no error initially', () => {
      expect(store.error).toBeNull()
    })

    it('should have null lastUpdated', () => {
      expect(store.lastUpdated).toBeNull()
    })
  })

  describe('Computed Properties', () => {
    describe('when summary is null', () => {
      it('totalFindings should be 0', () => {
        expect(store.totalFindings).toBe(0)
      })

      it('criticalCount should be 0', () => {
        expect(store.criticalCount).toBe(0)
      })

      it('severityData should be empty', () => {
        expect(store.severityData).toEqual([])
      })

      it('byProvider should be empty', () => {
        expect(store.byProvider).toEqual([])
      })

      it('byTool should be empty', () => {
        expect(store.byTool).toEqual([])
      })
    })

    describe('when summary has data', () => {
      beforeEach(() => {
        store.summary = {
          total: 100,
          critical: 10,
          high: 25,
          medium: 35,
          low: 20,
          info: 10,
          by_provider: { aws: 60, gcp: 40 },
          by_tool: { prowler: 50, scoutsuite: 50 },
        }
      })

      it('totalFindings should return correct count', () => {
        expect(store.totalFindings).toBe(100)
      })

      it('criticalCount should return correct count', () => {
        expect(store.criticalCount).toBe(10)
      })

      it('highCount should return correct count', () => {
        expect(store.highCount).toBe(25)
      })

      it('mediumCount should return correct count', () => {
        expect(store.mediumCount).toBe(35)
      })

      it('lowCount should return correct count', () => {
        expect(store.lowCount).toBe(20)
      })

      it('infoCount should return correct count', () => {
        expect(store.infoCount).toBe(10)
      })

      it('severityData should return formatted data with colors', () => {
        const data = store.severityData

        expect(data.length).toBe(5)
        expect(data[0]).toEqual({ label: 'Critical', value: 10, color: '#e74c3c' })
        expect(data[1]).toEqual({ label: 'High', value: 25, color: '#e67e22' })
      })

      it('severityData should filter out zero values', () => {
        store.summary.info = 0

        const data = store.severityData
        expect(data.find(d => d.label === 'Info')).toBeUndefined()
      })

      it('byProvider should return formatted data', () => {
        const data = store.byProvider

        expect(data).toContainEqual({ label: 'aws', value: 60 })
        expect(data).toContainEqual({ label: 'gcp', value: 40 })
      })

      it('byTool should return formatted data', () => {
        const data = store.byTool

        expect(data).toContainEqual({ label: 'prowler', value: 50 })
        expect(data).toContainEqual({ label: 'scoutsuite', value: 50 })
      })
    })
  })

  describe('fetchSummary', () => {
    it('should set loading to true during fetch', async () => {
      api.getSummary.mockResolvedValue({ total: 0 })

      const promise = store.fetchSummary()
      expect(store.loading).toBe(true)

      await promise
      expect(store.loading).toBe(false)
    })

    it('should populate summary on success', async () => {
      const mockSummary = {
        total: 50,
        critical: 5,
        high: 15,
        medium: 20,
        low: 10,
        info: 0,
        by_provider: { aws: 50 },
        by_tool: { prowler: 50 },
      }
      api.getSummary.mockResolvedValue(mockSummary)

      await store.fetchSummary()

      expect(store.summary).toEqual(mockSummary)
    })

    it('should update lastUpdated on success', async () => {
      api.getSummary.mockResolvedValue({ total: 0 })

      await store.fetchSummary()

      expect(store.lastUpdated).toBeInstanceOf(Date)
    })

    it('should handle API errors', async () => {
      api.getSummary.mockRejectedValue(new Error('Server error'))

      await store.fetchSummary()

      expect(store.error).toBe('Server error')
      expect(store.summary).toBeNull()
    })

    it('should clear error on successful fetch', async () => {
      store.error = 'Previous error'
      api.getSummary.mockResolvedValue({ total: 0 })

      await store.fetchSummary()

      expect(store.error).toBeNull()
    })
  })

  describe('startAutoRefresh', () => {
    it('should call fetchSummary immediately', () => {
      vi.useFakeTimers()
      api.getSummary.mockResolvedValue({ total: 0 })

      store.startAutoRefresh(30000)

      expect(api.getSummary).toHaveBeenCalledTimes(1)
      vi.useRealTimers()
    })

    it('should return interval ID', () => {
      vi.useFakeTimers()
      api.getSummary.mockResolvedValue({ total: 0 })

      const intervalId = store.startAutoRefresh(30000)

      expect(intervalId).toBeDefined()
      clearInterval(intervalId)
      vi.useRealTimers()
    })

    it('should refresh at specified interval', () => {
      vi.useFakeTimers()
      api.getSummary.mockResolvedValue({ total: 0 })

      const intervalId = store.startAutoRefresh(30000)

      vi.advanceTimersByTime(30000)
      expect(api.getSummary).toHaveBeenCalledTimes(2)

      vi.advanceTimersByTime(30000)
      expect(api.getSummary).toHaveBeenCalledTimes(3)

      clearInterval(intervalId)
      vi.useRealTimers()
    })
  })
})
