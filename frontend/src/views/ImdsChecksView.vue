<template>
  <div class="imds-checks-view">
    <div class="page-header">
      <div class="header-content">
        <h1>IMDS/Metadata Checks</h1>
        <p class="subtitle">
          Instance metadata service vulnerability checks
        </p>
      </div>
      <div class="header-actions">
        <Button
          v-if="!isRunning"
          v-tooltip.left="!hasAwsCredentials ? 'Select AWS profile in Credentials first' : ''"
          label="Run Scan"
          icon="pi pi-play"
          :loading="store.loading"
          :disabled="!hasAwsCredentials"
          @click="runScan"
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
      tool-name="IMDS scan"
      description="Scanning EC2 instances for IMDS v1 vulnerabilities. This checks instance metadata service configuration across your AWS account."
      :logs="executionLogs"
      @dismiss="dismissExecution"
      @view-results="refreshResults"
    >
      <template #stats>
        <div
          v-if="store.currentExecution?.status === 'completed' && store.currentExecution?.config"
          class="execution-stats"
        >
          <span>Instances scanned: <strong>{{ store.currentExecution.config.instances_checked || 0 }}</strong></span>
          <span>Vulnerabilities found: <strong>{{ store.currentExecution.config.vulnerabilities_found || 0 }}</strong></span>
          <span v-if="store.currentExecution.config.regions_scanned">
            Regions: <strong>{{ store.currentExecution.config.regions_scanned?.length || 0 }}</strong>
          </span>
        </div>
      </template>
    </ExecutionProgressPanel>

    <div
      v-if="store.summary"
      class="summary-cards"
    >
      <div class="summary-card info">
        <div class="card-value">
          {{ store.summary.total_instances }}
        </div>
        <div class="card-label">
          Total Instances
        </div>
      </div>
      <div class="summary-card critical">
        <div class="card-value">
          {{ store.summary.imds_v1_enabled }}
        </div>
        <div class="card-label">
          IMDSv1 Enabled
        </div>
      </div>
      <div class="summary-card high">
        <div class="card-value">
          {{ store.summary.ssrf_vulnerable }}
        </div>
        <div class="card-label">
          SSRF Vulnerable
        </div>
      </div>
      <div class="summary-card medium">
        <div class="card-value">
          {{ store.summary.container_exposed }}
        </div>
        <div class="card-label">
          Container Exposed
        </div>
      </div>
    </div>

    <div class="filters-section">
      <Button
        :label="showVulnerableOnly ? 'Show All' : 'Show Vulnerable'"
        :icon="showVulnerableOnly ? 'pi pi-list' : 'pi pi-exclamation-triangle'"
        @click="toggleVulnerable"
      />
    </div>

    <DataTable
      :value="store.checks"
      :loading="store.loading"
      responsive-layout="scroll"
      class="p-datatable-sm"
    >
      <template #empty>
        <div class="empty-state">
          <i class="pi pi-server" />
          <p>No IMDS check results found</p>
          <p class="empty-hint">
            Run a scan to check EC2 instances for IMDS vulnerabilities
          </p>
        </div>
      </template>
      <Column
        field="instance_id"
        header="Instance ID"
      />
      <Column
        field="instance_name"
        header="Name"
      />
      <Column
        field="region"
        header="Region"
      />
      <Column
        field="imds_v1_enabled"
        header="IMDSv1"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.imds_v1_enabled ? 'danger' : 'success'"
            :value="data.imds_v1_enabled ? 'Enabled' : 'Disabled'"
          />
        </template>
      </Column>
      <Column
        field="http_tokens_required"
        header="Tokens Required"
      >
        <template #body="{ data }">
          <Tag
            :severity="data.http_tokens_required ? 'success' : 'warning'"
            :value="data.http_tokens_required ? 'Yes' : 'No'"
          />
        </template>
      </Column>
      <Column
        field="ssrf_vulnerable"
        header="SSRF"
      >
        <template #body="{ data }">
          <i :class="data.ssrf_vulnerable ? 'pi pi-exclamation-triangle text-danger' : 'pi pi-check text-success'" />
        </template>
      </Column>
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
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useImdsChecksStore } from '../stores/imdsChecks'
import { useExecutionsStore } from '../stores/executions'
import { useCredentialsStore } from '../stores/credentials'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import Button from 'primevue/button'
import Paginator from 'primevue/paginator'
import ExecutionProgressPanel from '../components/executions/ExecutionProgressPanel.vue'

const store = useImdsChecksStore()
const executionsStore = useExecutionsStore()
const credentialsStore = useCredentialsStore()
const toast = useToast()
const showVulnerableOnly = ref(false)
const executionLogs = ref(null)

const hasAwsCredentials = computed(() => {
  return credentialsStore.sessionCredentials?.aws !== null
})

const isRunning = computed(() =>
  store.currentExecution?.status === 'running',
)

function getRiskSeverity(level) {
  const map = { critical: 'danger', high: 'warning', medium: 'info', low: 'success' }
  return map[level] || 'secondary'
}

function toggleVulnerable() {
  showVulnerableOnly.value = !showVulnerableOnly.value
  if (showVulnerableOnly.value) {
    store.fetchVulnerable()
  } else {
    store.fetchChecks()
  }
}

async function refreshResults() {
  await Promise.all([
    store.fetchChecks(),
    store.fetchSummary(),
  ])
  toast.add({
    severity: 'info',
    summary: 'Results Loaded',
    detail: `Found ${store.pagination.total} instance(s)`,
    life: 3000,
  })
}

async function runScan() {
  if (!hasAwsCredentials.value) {
    toast.add({
      severity: 'warn',
      summary: 'No Credentials',
      detail: 'Select an AWS profile in Credentials first',
      life: 3000,
    })
    return
  }
  executionLogs.value = null
  try {
    await store.runScan({})
    toast.add({
      severity: 'info',
      summary: 'Scan Started',
      detail: 'IMDS vulnerability scan is now running',
      life: 3000,
    })
  } catch (e) {
    toast.add({
      severity: 'error',
      summary: 'Scan Failed',
      detail: e.message || 'Failed to start IMDS scan',
      life: 5000,
    })
  }
}

async function stopExecution() {
  await store.stopCurrentExecution()
  toast.add({
    severity: 'warn',
    summary: 'Scan Stopped',
    detail: 'IMDS scan was cancelled',
    life: 3000,
  })
}

// Watch for execution status changes to show completion notifications
watch(
  () => store.currentExecution?.status,
  (newStatus, oldStatus) => {
    if (oldStatus === 'running' && newStatus === 'completed') {
      toast.add({
        severity: 'success',
        summary: 'Scan Completed',
        detail: 'IMDS vulnerability scan finished successfully',
        life: 4000,
      })
    } else if (oldStatus === 'running' && newStatus === 'failed') {
      toast.add({
        severity: 'error',
        summary: 'Scan Failed',
        detail: store.currentExecution?.error || 'IMDS scan encountered an error',
        life: 5000,
      })
    }
  },
)

function dismissExecution() {
  store.currentExecution = null
  executionLogs.value = null
}

function onPageChange(event) {
  store.pagination.page = event.page + 1
  if (showVulnerableOnly.value) {
    store.fetchVulnerable()
  } else {
    store.fetchChecks()
  }
}

onMounted(() => {
  store.fetchChecks()
  store.fetchSummary()
})

onUnmounted(() => {
  // Stop any polling when leaving the view
  if (store.currentExecution?.execution_id) {
    executionsStore.stopPolling(store.currentExecution.execution_id)
  }
})
</script>

<style scoped>
.imds-checks-view { padding: 1.5rem; }
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.5rem; }
.page-header h1 { margin: 0; font-size: 1.75rem; }
.subtitle { color: var(--text-color-secondary); margin-top: 0.25rem; }

.execution-stats {
  margin-top: 0.75rem;
  display: flex;
  gap: 1.5rem;
  font-size: 0.9rem;
  color: var(--text-color-secondary);
}
.execution-stats strong {
  color: var(--text-color);
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  color: var(--text-color-secondary);
}
.empty-state i {
  font-size: 3rem;
  margin-bottom: 1rem;
  opacity: 0.5;
}
.empty-state p {
  margin: 0.25rem 0;
}
.empty-hint {
  font-size: 0.85rem;
  opacity: 0.7;
}

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
.summary-card.critical { border-left-color: var(--red-500); }
.summary-card.high { border-left-color: var(--orange-500); }
.summary-card.medium { border-left-color: var(--yellow-500); }
.summary-card.info { border-left-color: var(--blue-500); }
.card-value { font-size: 1.5rem; font-weight: bold; }
.card-label { color: var(--text-color-secondary); }
.filters-section { margin-bottom: 1rem; }
.text-danger { color: var(--red-500); }
.text-success { color: var(--green-500); }
</style>
