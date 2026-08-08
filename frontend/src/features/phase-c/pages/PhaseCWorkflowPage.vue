<template>
  <main class="page">
    <page-header title="MAP / C_FAST 离线工件工作流" subtitle="Phase C 控制投影：浏览器不签名、不持有私钥，也不能启动执行。" />
    <n-alert type="warning" title="OFFLINE_FAKE_ONLY" class="notice">
      当前仅验证跨服务交接合同。即使提交 Enable，effective state 仍是 DISABLED，所有交易及生产 authority 均为 false。
    </n-alert>

    <n-grid :cols="isMobile ? 1 : 3" :x-gap="12" :y-gap="12">
      <n-gi><n-card title="MAP"><n-tag>{{ workflow?.map_status ?? 'loading' }}</n-tag></n-card></n-gi>
      <n-gi><n-card title="C_FAST"><n-tag>{{ workflow?.c_fast_status ?? 'loading' }}</n-tag></n-card></n-gi>
      <n-gi><n-card title="Runtime Authorization"><n-tag type="warning">{{ authorization?.effective_state ?? 'loading' }}</n-tag></n-card></n-gi>
    </n-grid>

    <n-card title="1. 导出离线 signing request" class="section">
      <n-space vertical>
        <n-select v-model:value="domain" :options="domainOptions" />
        <n-input v-model:value="artifactText" type="textarea" :rows="7" aria-label="unsigned artifact JSON" />
        <n-button type="primary" :loading="exporting" @click="exportRequest">导出请求</n-button>
        <n-alert v-if="signingRequest" type="info" title="仅供离线 signer 使用">
          <pre>{{ JSON.stringify(signingRequest, null, 2) }}</pre>
        </n-alert>
      </n-space>
    </n-card>

    <n-card title="2. 上传已经离线签名的 artifact 并请求 custody verify/install" class="section">
      <n-space vertical>
        <n-input v-model:value="signedArtifactText" type="textarea" :rows="7" placeholder="粘贴 signed artifact JSON；本页面不会签名" aria-label="signed artifact JSON" />
        <n-button :loading="uploading" @click="uploadArtifact">上传并请求安装</n-button>
        <n-alert v-if="receipt" type="success" title="Custody receipt projection">
          {{ receipt.receipt_id }} · artifact {{ receipt.artifact_id }} · version {{ receipt.custody_version }}
        </n-alert>
      </n-space>
    </n-card>

    <n-card title="3. Runtime Authorization typed command" class="section">
      <n-space vertical>
        <n-input v-model:value="reason" placeholder="审计原因（至少 3 个字符）" />
        <n-space>
          <n-button type="warning" :disabled="!receipt" @click="submitAuthorization('enable')">提交 Enable request</n-button>
          <n-button :disabled="!receipt" @click="submitAuthorization('revoke')">提交 Revoke request</n-button>
        </n-space>
        <n-descriptions v-if="authorization" :column="isMobile ? 1 : 3" bordered size="small">
          <n-descriptions-item label="requested">{{ authorization.requested_state }}</n-descriptions-item>
          <n-descriptions-item label="effective">{{ authorization.effective_state }}</n-descriptions-item>
          <n-descriptions-item label="runtime mutation">{{ authorization.runtime_mutation_allowed }}</n-descriptions-item>
        </n-descriptions>
      </n-space>
    </n-card>

    <n-card title="Execution preview / status / audit archive (read-only)" class="section">
      <n-descriptions v-if="execution" :column="isMobile ? 1 : 3" bordered size="small">
        <n-descriptions-item label="status">{{ execution.status }}</n-descriptions-item>
        <n-descriptions-item label="execution mutation">{{ execution.execution_mutation_allowed }}</n-descriptions-item>
        <n-descriptions-item label="audit / archive">{{ execution.audit.length }} / {{ execution.archive.length }}</n-descriptions-item>
      </n-descriptions>
    </n-card>
  </main>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { NAlert, NButton, NCard, NDescriptions, NDescriptionsItem, NGi, NGrid, NInput, NSelect, NSpace, NTag, useMessage } from 'naive-ui'
import PageHeader from '../../../components/common/PageHeader.vue'
import { useMediaQuery } from '../../../composables/useMediaQuery'
import {
  submitPhaseCAuthorizationWithRecovery,
  exportPhaseCSigningRequest,
  getPhaseCAuthorizationStatus,
  getPhaseCExecutionProjection,
  getPhaseCWorkflowStatus,
  uploadAndInstallPhaseCSignedArtifact,
  type AuthorizationStatus,
  type CustodyReceipt,
  type ExecutionProjection,
  type PhaseCWorkflowStatus,
  type SigningRequestExport
} from '../../../api/phaseCWorkflow'

const message = useMessage()
const isMobile = useMediaQuery('(max-width: 760px)')
const workflow = ref<PhaseCWorkflowStatus>()
const authorization = ref<AuthorizationStatus>()
const execution = ref<ExecutionProjection>()
const receipt = ref<CustodyReceipt>()
const signingRequest = ref<SigningRequestExport>()
const exporting = ref(false)
const uploading = ref(false)
const domain = ref<'map_acceptance' | 'c_fast_acceptance' | 'runtime_authorization'>('runtime_authorization')
const reason = ref('offline workflow request')
const artifactText = ref(JSON.stringify({
  artifact_id: `artifact-${'0'.repeat(64)}`,
  artifact_type: 'runtime-authorization',
  payload: { production_allowed: false, live_trading_authorized: false, countable_forward: false }
}, null, 2))
const signedArtifactText = ref('')
const domainOptions = [
  { label: 'MAP acceptance', value: 'map_acceptance' },
  { label: 'C_FAST acceptance', value: 'c_fast_acceptance' },
  { label: 'Runtime authorization', value: 'runtime_authorization' }
]

function id(prefix: string) { return `${prefix}-${crypto.randomUUID()}` }
function parseObject(text: string): Record<string, unknown> {
  const value: unknown = JSON.parse(text)
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new Error('JSON 必须为 object')
  return value as Record<string, unknown>
}
async function refresh() {
  ;[workflow.value, authorization.value, execution.value] = await Promise.all([
    getPhaseCWorkflowStatus(), getPhaseCAuthorizationStatus(), getPhaseCExecutionProjection()
  ])
}
async function exportRequest() {
  try {
    exporting.value = true
    signingRequest.value = await exportPhaseCSigningRequest({ request_id: id('signing-request'), domain: domain.value, key_id: 'offline-signer-key', key_version: 'v1', requested_at: new Date().toISOString(), expires_at: new Date(Date.now() + 300000).toISOString(), artifact: parseObject(artifactText.value) })
  } catch (error) { message.error(error instanceof Error ? error.message : '导出失败') } finally { exporting.value = false }
}
async function uploadArtifact() {
  try {
    uploading.value = true
    receipt.value = await uploadAndInstallPhaseCSignedArtifact({
      idempotency_key: id('custody'), expected_custody_version: receipt.value?.custody_version ?? 0,
      signing_request_id: signingRequest.value?.request_id ?? 'offline-request-required', correlation_id: id('correlation'), signed_artifact: parseObject(signedArtifactText.value)
    })
  } catch (error) { message.error(error instanceof Error ? error.message : '上传失败') } finally { uploading.value = false }
}
async function submitAuthorization(action: 'enable' | 'revoke') {
  if (!receipt.value || !authorization.value) return
  try {
    authorization.value = await submitPhaseCAuthorizationWithRecovery({
      command_id: id('authorization-command'), idempotency_key: id('authorization'), expected_version: authorization.value.version,
      action, authorization_artifact_id: receipt.value.artifact_id, custody_receipt_id: receipt.value.receipt_id, reason: reason.value
    })
    await refresh()
  } catch (error) { message.error(error instanceof Error ? error.message : '命令被拒绝') }
}
onMounted(() => { void refresh().catch(error => message.error(error instanceof Error ? error.message : '读取状态失败')) })
</script>

<style scoped>
.notice, .section { margin-top: 16px; }
pre { margin: 0; overflow: auto; white-space: pre-wrap; word-break: break-word; }
</style>
