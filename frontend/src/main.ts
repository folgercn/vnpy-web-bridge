import { createApp } from 'vue'
import { createPinia } from 'pinia'
import {
  NAlert,
  NButton,
  NCard,
  NConfigProvider,
  NDataTable,
  NDialogProvider,
  NDrawer,
  NDrawerContent,
  NDropdown,
  NForm,
  NFormItem,
  NIcon,
  NInput,
  NInputNumber,
  NLayout,
  NLayoutContent,
  NLayoutHeader,
  NLayoutSider,
  NMenu,
  NMessageProvider,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NStatistic,
  NTag
} from 'naive-ui'
import App from './App.vue'
import { router } from './router'
import './styles/app.css'

const app = createApp(App)
const naiveComponents = [
  NAlert,
  NButton,
  NCard,
  NConfigProvider,
  NDataTable,
  NDialogProvider,
  NDrawer,
  NDrawerContent,
  NDropdown,
  NForm,
  NFormItem,
  NIcon,
  NInput,
  NInputNumber,
  NLayout,
  NLayoutContent,
  NLayoutHeader,
  NLayoutSider,
  NMenu,
  NMessageProvider,
  NRadioButton,
  NRadioGroup,
  NSelect,
  NStatistic,
  NTag
]

for (const component of naiveComponents) {
  if (component.name) app.component(component.name, component)
}

app.use(createPinia()).use(router).mount('#app')
