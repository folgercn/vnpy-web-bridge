<template>
  <div class="page">
    <n-alert v-if="!terminal.webTradeEnabled" type="warning">Web 交易关闭，不能下单、撤单或全撤。</n-alert>
    <div class="grid-2">
      <n-card title="限价下单" size="small">
        <n-form :model="form" label-placement="left" label-width="90">
          <n-form-item label="合约"><n-input v-model:value="form.symbol" /></n-form-item>
          <n-form-item label="交易所"><n-select v-model:value="form.exchange" :options="exchangeOptions" /></n-form-item>
          <n-form-item label="方向"><n-radio-group v-model:value="form.direction"><n-radio-button value="long">多</n-radio-button><n-radio-button value="short">空</n-radio-button></n-radio-group></n-form-item>
          <n-form-item label="开平"><n-select v-model:value="form.offset" :options="offsetOptions" /></n-form-item>
          <n-form-item label="价格"><n-input-number v-model:value="form.price" :min="0" /></n-form-item>
          <n-form-item label="手数"><n-input-number v-model:value="form.volume" :min="1" /></n-form-item>
          <n-button type="primary" :disabled="!terminal.webTradeEnabled" @click="confirmOrder">下单</n-button>
        </n-form>
      </n-card>
      <data-panel title="当前委托" :columns="orderColumns" :rows="terminal.orders" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive } from 'vue'
import { useDialog, useMessage } from 'naive-ui'
import DataPanel from '../components/common/DataPanel.vue'
import { sendOrder } from '../api/trade'
import { exchangeOptions } from '../constants/exchanges'
import { useTerminalStore } from '../stores/terminal'

const dialog = useDialog()
const message = useMessage()
const terminal = useTerminalStore()
const form = reactive({ symbol: 'rb2610', exchange: 'SHFE', direction: 'long' as const, offset: 'open' as const, price: 3000, volume: 1 })
const offsetOptions = [
  { label: '开仓', value: 'open' },
  { label: '平仓', value: 'close' },
  { label: '平今', value: 'closetoday' },
  { label: '平昨', value: 'closeyesterday' }
]
const orderColumns = ['vt_orderid', 'vt_symbol', 'direction', 'offset', 'price', 'volume', 'traded', 'status'].map((key) => ({ title: key, key }))

function confirmOrder() {
  dialog.warning({
    title: '确认下单',
    content: `合约：${form.symbol}.${form.exchange}\n方向：${form.direction}\n开平：${form.offset}\n价格：${form.price}\n手数：${form.volume}`,
    positiveText: '确认',
    negativeText: '取消',
    onPositiveClick: submitOrder
  })
}

async function submitOrder() {
  try {
    const result = await sendOrder({ ...form, type: 'limit', confirm: true })
    message.success(`下单已提交：${String(result.vt_orderid)}`)
    await terminal.refreshSnapshots()
  } catch (exc) {
    message.error(exc instanceof Error ? exc.message : '下单失败')
  }
}
</script>
