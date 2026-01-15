<template>
  <div class="cloudfox-view">
    <div class="page-header">
      <div class="header-content">
        <h1>CloudFox</h1>
        <p class="subtitle">
          AWS/Azure/GCP enumeration results
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          label="Run CloudFox"
          icon="pi pi-play"
          :loading="store.loading"
          @click="runCloudfox"
        />
        <Button
          v-else
          label="Stop"
          icon="pi pi-stop"
          severity="danger"
          @click="stopExecution"
        />
      </div>
    </div>

    <!-- Execution Status Panel -->
    <ExecutionProgressPanel
      :execution="store.currentExecution"
      tool-name="CloudFox"
      description="Running CloudFox AWS enumeration. This discovers attack paths and privilege escalation opportunities."
      :logs="executionLogs"
      @dismiss="dismissExecution"
      @view-results="store.fetchResults()"
    />

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_results }}
        </div>
        <div class="card-label">
          Total Results
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Dropdown
        v-model="filters.moduleName"
        :options="moduleOptions"
        placeholder="Module"
        class="filter-dropdown"
        @change="applyFilters"
      />
      <Dropdown
        v-model="filters.riskLevel"
        :options="riskLevels"
        placeholder="Risk Level"
        class="filter-dropdown"
        @change="applyFilters"
      />
    </div>

    <DataTable
      :value="store.results"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <Column
        field="module_name"
        header="Module"
      />
      <Column
        field="resource_name"
        header="Resource"
      />
      <Column
        field="resource_arn"
        header="ARN"
      >
        <template #body="{ data }">
          <span class="arn-text">{{ truncate(data.resource_arn, 50) }}</span>
        </template>
      </Column>
      <Column
        field="finding_category"
        header="Category"
      />
      <Column
        field="cloud_provider"
        header="Provider"
      />
      <Column
        field="risk_level"
        header="Risk"
      >
        <template #body="{ data }">
          <Tag
            :severity="getRiskSeverity(data.risk_level)"
            :value="data.risk_level"
          />
        </template>
      </Column>
    </DataTable>

    <Paginator
      v-if="store.pagination.total > store.pagination.pageSize"
      :rows="store.pagination.pageSize"
      :total-records="store.pagination.total"
      :first="(store.pagination.page - 1) * store.pagination.pageSize"
      @page="onPageChange"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useCloudfoxStore } from '../stores/cloudfox'
import { useExecutionsStore } from '../stores/executions'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Paginator from 'primevue/paginator'
import ExecutionProgressPanel from '../components/executions/ExecutionProgressPanel.vue'

const store = useCloudfoxStore()
const executionsStore = useExecutionsStore()

const filters = ref({
  moduleName: null,
  riskLevel: null,
})

const executionLogs = ref(null)

const moduleOptions = ['all-checks', 'iam', 'buckets', 'secrets', 'lambda', 'env-vars', 'permissions']
const riskLevels = ['critical', 'high', 'medium', 'low']

const isRunning = computed(() =>
  store.currentExecution?.status === 'running',
)

function truncate(str, len) {
  if (!str) return ''
  return str.length > len ? str.slice(0, len) + '...' : str
}

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function applyFilters() {
  store.setFilters(filters.value)
}

async function runCloudfox() {
  executionLogs.value = null
  await store.runCloudfox({ modules: ['all'] })
}

async function stopExecution() {
  await store.stopCurrentExecution()
}

function dismissExecution() {
  store.currentExecution = null
  executionLogs.value = null
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  store.fetchResults()
}

onMounted(() => {
  store.fetchResults()
  store.fetchSummary()
  store.fetchModules()
})

onUnmounted(() => {
  // Stop any polling when leaving the view
  if (store.currentExecution?.execution_id) {
    executionsStore.stopPolling(store.currentExecution.execution_id)
  }
})
</script>

<style scoped>
.cloudfox-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}
.summary-card {
  padding: 1rem;
  border-radius: 8px;
  background: var(--surface-card);
  border-left: 4px solid;
}
.summary-card.info { border-left-color: var(--blue-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { display: flex; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }
.filter-dropdown { min-width: 150px; }
.arn-text { font-family: monospace; font-size: 0.85rem; }
</style>
