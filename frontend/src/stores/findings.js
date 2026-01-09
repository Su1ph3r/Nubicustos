import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import api from '../services/api'

export const useFindingsStore = defineStore('findings', () => {
  // State
  const findings = ref([])
  const currentFinding = ref(null)
  const total = ref(0)
  const page = ref(1)
  const pageSize = ref(50)
  const loading = ref(false)
  const error = ref(null)

  // Filters
  const filters = ref({
    severity: null,
    status: null,
    tool: null,
    cloud_provider: null,
    resource_type: null,
    search: ''
  })

  // Available filter options (populated from data)
  const filterOptions = ref({
    severities: ['critical', 'high', 'medium', 'low', 'info'],
    statuses: ['open', 'closed', 'mitigated', 'accepted'],
    tools: [],
    cloudProviders: [],
    resourceTypes: []
  })

  // Computed
  const hasFilters = computed(() => {
    return Object.values(filters.value).some(v => v !== null && v !== '')
  })

  const totalPages = computed(() => {
    return Math.ceil(total.value / pageSize.value)
  })

  // Actions
  async function fetchFindings() {
    loading.value = true
    error.value = null

    try {
      const params = {
        page: page.value,
        page_size: pageSize.value,
        ...filters.value
      }

      // Remove null/empty filter values
      Object.keys(params).forEach(key => {
        if (params[key] === null || params[key] === '') {
          delete params[key]
        }
      })

      const response = await api.getFindings(params)
      findings.value = response.findings || []
      total.value = response.total || 0

      // Extract unique filter options from data
      updateFilterOptions(findings.value)
    } catch (err) {
      error.value = err.message
      findings.value = []
      total.value = 0
    } finally {
      loading.value = false
    }
  }

  async function fetchFinding(id) {
    loading.value = true
    error.value = null

    try {
      currentFinding.value = await api.getFinding(id)
    } catch (err) {
      error.value = err.message
      currentFinding.value = null
    } finally {
      loading.value = false
    }
  }

  async function updateFinding(id, data) {
    try {
      const updated = await api.updateFinding(id, data)

      // Update in local list if present
      const index = findings.value.findIndex(f => f.id === id)
      if (index !== -1) {
        findings.value[index] = { ...findings.value[index], ...updated }
      }

      // Update current finding if it's the same
      if (currentFinding.value?.id === id) {
        currentFinding.value = { ...currentFinding.value, ...updated }
      }

      return updated
    } catch (err) {
      error.value = err.message
      throw err
    }
  }

  function updateFilterOptions(data) {
    const tools = new Set()
    const providers = new Set()
    const resourceTypes = new Set()

    data.forEach(finding => {
      if (finding.tool) tools.add(finding.tool)
      if (finding.cloud_provider) providers.add(finding.cloud_provider)
      if (finding.resource_type) resourceTypes.add(finding.resource_type)
    })

    // Only update if we have new options
    if (tools.size > 0) {
      filterOptions.value.tools = [...tools].sort()
    }
    if (providers.size > 0) {
      filterOptions.value.cloudProviders = [...providers].sort()
    }
    if (resourceTypes.size > 0) {
      filterOptions.value.resourceTypes = [...resourceTypes].sort()
    }
  }

  function setFilter(key, value) {
    filters.value[key] = value
    page.value = 1 // Reset to first page when filtering
  }

  function clearFilters() {
    filters.value = {
      severity: null,
      status: null,
      tool: null,
      cloud_provider: null,
      resource_type: null,
      search: ''
    }
    page.value = 1
  }

  function setPage(newPage) {
    page.value = newPage
  }

  function setPageSize(newSize) {
    pageSize.value = newSize
    page.value = 1
  }

  return {
    // State
    findings,
    currentFinding,
    total,
    page,
    pageSize,
    loading,
    error,
    filters,
    filterOptions,

    // Computed
    hasFilters,
    totalPages,

    // Actions
    fetchFindings,
    fetchFinding,
    updateFinding,
    setFilter,
    clearFilters,
    setPage,
    setPageSize
  }
})
