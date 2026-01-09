<template>
  <div class="filters-container">
    <div class="filters-row">
      <div class="filter-group">
        <label>Search</label>
        <InputText
          v-model="searchQuery"
          placeholder="Search findings..."
          @input="handleSearchDebounced"
        />
      </div>

      <div class="filter-group">
        <label>Severity</label>
        <MultiSelect
          v-model="selectedSeverities"
          :options="severityOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="All Severities"
          display="chip"
          @change="handleSeverityChange"
        />
      </div>

      <div class="filter-group">
        <label>Status</label>
        <MultiSelect
          v-model="selectedStatuses"
          :options="statusOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="All Statuses"
          display="chip"
          @change="handleStatusChange"
        />
      </div>

      <div class="filter-group">
        <label>Tool</label>
        <Dropdown
          v-model="selectedTool"
          :options="toolOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="All Tools"
          showClear
          @change="handleToolChange"
        />
      </div>

      <div class="filter-group">
        <label>Provider</label>
        <Dropdown
          v-model="selectedProvider"
          :options="providerOptions"
          optionLabel="label"
          optionValue="value"
          placeholder="All Providers"
          showClear
          @change="handleProviderChange"
        />
      </div>

      <div class="filter-actions">
        <Button
          v-if="hasFilters"
          label="Clear"
          icon="pi pi-times"
          severity="secondary"
          size="small"
          @click="clearFilters"
        />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useFindingsStore } from '../../stores/findings'

const emit = defineEmits(['filter-change'])
const findingsStore = useFindingsStore()

// Local state
const searchQuery = ref(findingsStore.filters.search || '')
const selectedSeverities = ref(findingsStore.filters.severity ? [findingsStore.filters.severity] : [])
const selectedStatuses = ref(findingsStore.filters.status ? [findingsStore.filters.status] : [])
const selectedTool = ref(findingsStore.filters.tool || null)
const selectedProvider = ref(findingsStore.filters.cloud_provider || null)

// Debounce timer
let searchDebounceTimer = null

// Options
const severityOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
  { label: 'Info', value: 'info' }
]

const statusOptions = [
  { label: 'Open', value: 'open' },
  { label: 'Closed', value: 'closed' },
  { label: 'Mitigated', value: 'mitigated' },
  { label: 'Accepted', value: 'accepted' }
]

const toolOptions = computed(() =>
  findingsStore.filterOptions.tools.map(t => ({ label: t, value: t }))
)

const providerOptions = computed(() =>
  findingsStore.filterOptions.cloudProviders.map(p => ({ label: p, value: p }))
)

const hasFilters = computed(() => findingsStore.hasFilters)

// Handlers
const handleSearchDebounced = () => {
  clearTimeout(searchDebounceTimer)
  searchDebounceTimer = setTimeout(() => {
    findingsStore.setFilter('search', searchQuery.value)
    emit('filter-change')
  }, 300)
}

const handleSeverityChange = () => {
  const value = selectedSeverities.value.length > 0 ? selectedSeverities.value.join(',') : null
  findingsStore.setFilter('severity', value)
  emit('filter-change')
}

const handleStatusChange = () => {
  const value = selectedStatuses.value.length > 0 ? selectedStatuses.value.join(',') : null
  findingsStore.setFilter('status', value)
  emit('filter-change')
}

const handleToolChange = () => {
  findingsStore.setFilter('tool', selectedTool.value)
  emit('filter-change')
}

const handleProviderChange = () => {
  findingsStore.setFilter('cloud_provider', selectedProvider.value)
  emit('filter-change')
}

const clearFilters = () => {
  searchQuery.value = ''
  selectedSeverities.value = []
  selectedStatuses.value = []
  selectedTool.value = null
  selectedProvider.value = null
  findingsStore.clearFilters()
  emit('filter-change')
}

// Sync with store when filters change externally
watch(() => findingsStore.filters, (newFilters) => {
  if (newFilters.search !== searchQuery.value) {
    searchQuery.value = newFilters.search || ''
  }
  if (newFilters.severity) {
    selectedSeverities.value = newFilters.severity.split(',')
  }
}, { deep: true })
</script>

<style scoped>
.filters-container {
  background: var(--bg-secondary);
  border-radius: var(--radius-md);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
  box-shadow: var(--shadow-md);
}

.filters-row {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  align-items: flex-end;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  min-width: 150px;
}

.filter-group label {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--text-secondary);
  text-transform: uppercase;
}

.filter-group :deep(.p-inputtext),
.filter-group :deep(.p-dropdown),
.filter-group :deep(.p-multiselect) {
  width: 100%;
}

.filter-actions {
  display: flex;
  align-items: center;
  margin-left: auto;
}

@media (max-width: 768px) {
  .filters-row {
    flex-direction: column;
  }

  .filter-group {
    width: 100%;
  }

  .filter-actions {
    width: 100%;
    margin-left: 0;
    justify-content: flex-end;
  }
}
</style>
