import { mount, shallowMount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import ActionBar from '../components/common/ActionBar.vue'
import ResponsiveDataTable from '../components/common/ResponsiveDataTable.vue'

const viewport = vi.hoisted(() => ({ mobile: false }))

vi.mock('../composables/useMediaQuery', () => ({
  useMediaQuery: () => viewport.mobile
}))

describe('shared frontend components', () => {
  it('separates normal and destructive actions', () => {
    const wrapper = mount(ActionBar, {
      slots: {
        default: '<button>恢复持续授权</button>',
        danger: '<button>停止</button>'
      }
    })

    expect(wrapper.find('.action-bar__main').text()).toBe('恢复持续授权')
    expect(wrapper.find('.action-bar__danger').text()).toBe('停止')
  })

  it.each([
    [false, 'medium'],
    [true, 'small']
  ])('uses the expected table size when mobile=%s', (mobile, expectedSize) => {
    viewport.mobile = mobile
    const wrapper = shallowMount(ResponsiveDataTable, {
      props: {
        columns: [{ title: '名称', key: 'name' }],
        data: [{ name: 'demo' }],
        size: 'medium'
      }
    })

    expect(wrapper.findComponent({ name: 'DataTable' }).props('size')).toBe(expectedSize)
  })
})
