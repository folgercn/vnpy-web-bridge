import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import Strategies from '../pages/Strategies.vue'

describe('Phase A strategy surface', () => {
  it('is explicitly unavailable and exposes no legacy operation controls', () => {
    const wrapper = mount(Strategies, { global: { stubs: { NAlert: { template: '<section><slot /></section>' } } } })

    expect(wrapper.text()).toContain('Phase A')
    expect(wrapper.text()).toContain('不会读取或调用旧策略执行 API')
    expect(wrapper.find('button').exists()).toBe(false)
  })
})
