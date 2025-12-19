import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createElement } from 'react'
import { createRoot } from 'react-dom/client'
import type { Root } from 'react-dom/client'
import RulesList from '../RulesList'
import type { WAFRule } from '../../../types/waf'

describe('RulesList Component', () => {
  let container: HTMLDivElement
  let root: Root

  const mockOnEdit = vi.fn()
  const mockOnDelete = vi.fn()
  const mockOnToggle = vi.fn()
  const mockOnViewDetails = vi.fn()

  const mockDefaultRules: WAFRule[] = [
    {
      id: 'default-1',
      name: 'SQL Injection Protection',
      description: 'Protects against SQL injection attacks',
      type: 'sqli',
      severity: 'CRITICAL',
      enabled: true,
      is_default: true,
    },
    {
      id: 'default-2',
      name: 'XSS Protection',
      description: 'Protects against XSS attacks',
      type: 'xss',
      severity: 'HIGH',
      enabled: true,
      is_default: true,
    },
    {
      id: 'default-3',
      name: 'LFI Protection',
      description: 'Local File Inclusion protection',
      type: 'lfi',
      severity: 'MEDIUM',
      enabled: true,
      is_default: true,
    },
  ]

  const mockCustomRules: WAFRule[] = [
    {
      id: 'custom-1',
      name: 'Custom Block Rule',
      description: 'Custom rule for blocking',
      type: 'custom',
      threatType: 'custom',
      mode: 'block',
      action: 'block',
      enabled: true,
      createdAt: '2024-01-15T10:30:00Z',
      updatedAt: '2024-01-20T14:45:00Z',
    },
    {
      id: 'custom-2',
      name: 'Custom Detect Rule',
      description: 'Custom rule for detecting',
      type: 'detection',
      threatType: 'detection',
      mode: 'detect',
      action: 'detect',
      enabled: false,
      createdAt: '2024-02-01T08:00:00Z',
      updatedAt: '2024-02-10T09:15:00Z',
    },
    {
      id: 'custom-3',
      name: 'Manual Block IP',
      description: 'Manually blocked IP',
      type: 'manual',
      mode: 'block',
      enabled: true,
      createdAt: '2024-03-01T12:00:00Z',
      updatedAt: '2024-03-01T12:00:00Z',
    },
  ]

  beforeEach(() => {
    container = document.createElement('div')
    document.body.appendChild(container)
    vi.clearAllMocks()
  })

  afterEach(() => {
    if (root) {
      root.unmount()
    }
    if (container && document.body.contains(container)) {
      document.body.removeChild(container)
    }
  })

  const renderComponent = (props: any) => {
    return new Promise<void>((resolve) => {
      root = createRoot(container)
      root.render(createElement(RulesList, props))
      setTimeout(resolve, 100)
    })
  }

  describe('Basic Rendering', () => {
    it('should render empty state when no rules provided', async () => {
      await renderComponent({
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('No rules found')
    })

    it('should render default rules', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('SQL Injection Protection')
      expect(container.textContent).toContain('XSS Protection')
      expect(container.textContent).toContain('LFI Protection')
    })

    it('should render custom rules', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Custom Block Rule')
      expect(container.textContent).toContain('Custom Detect Rule')
      expect(container.textContent).toContain('Manual Block IP')
    })

    it('should render both default and custom rules', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('SQL Injection Protection')
      expect(container.textContent).toContain('Custom Block Rule')
    })

    it('should display correct summary count', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toMatch(/6 rules/)
      expect(container.textContent).toMatch(/3 default/)
      expect(container.textContent).toMatch(/3 custom/)
    })

    it('should use singular form for 1 rule', async () => {
      await renderComponent({
        defaultRules: [mockDefaultRules[0]],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toMatch(/1 rule/)
    })
  })

  describe('Search Functionality', () => {
    it('should filter rules by search term', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const searchInput = container.querySelector('input[placeholder="Search by name..."]') as HTMLInputElement
      expect(searchInput).toBeTruthy()

      // Simula input utente
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(searchInput, 'SQL')
      searchInput.dispatchEvent(new Event('input', { bubbles: true }))
      searchInput.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 200))

      expect(container.textContent).toContain('SQL Injection Protection')
      // Dopo il filtro dovrebbe mostrare solo 1 rule
      const rows = container.querySelectorAll('tbody tr')
      expect(rows.length).toBe(1)
    })

    it('should be case-insensitive', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const searchInput = container.querySelector('input[placeholder="Search by name..."]') as HTMLInputElement
      searchInput.value = 'sql'
      searchInput.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(container.textContent).toContain('SQL Injection Protection')
    })

    it('should show empty state when no matches', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const searchInput = container.querySelector('input[placeholder="Search by name..."]') as HTMLInputElement
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(searchInput, 'nonexistent')
      searchInput.dispatchEvent(new Event('input', { bubbles: true }))
      searchInput.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 200))

      // Non dovrebbero esserci righe nella tabella
      const rows = container.querySelectorAll('tbody tr')
      expect(rows.length).toBe(0)
    })

    it('should filter by description as well', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const searchInput = container.querySelector('input[placeholder="Search by name..."]') as HTMLInputElement
      searchInput.value = 'injection attacks'
      searchInput.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(container.textContent).toContain('SQL Injection Protection')
    })
  })

  describe('Threat Type Filter', () => {
    it('should filter by threat type', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const threatTypeSelect = container.querySelector('select') as HTMLSelectElement
      expect(threatTypeSelect).toBeTruthy()

      const options = Array.from(threatTypeSelect.options)
      const sqliOption = options.find((opt) => opt.value === 'sqli')
      if (sqliOption) {
        threatTypeSelect.value = 'sqli'
        threatTypeSelect.dispatchEvent(new Event('change', { bubbles: true }))

        await new Promise((resolve) => setTimeout(resolve, 100))

        expect(container.textContent).toContain('SQL Injection Protection')
        expect(container.textContent).not.toContain('XSS Protection')
      }
    })

    it('should show all rules when "all" is selected', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const selects = container.querySelectorAll('select')
      const threatTypeSelect = selects[0] as HTMLSelectElement

      threatTypeSelect.value = 'all'
      threatTypeSelect.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(container.textContent).toContain('SQL Injection Protection')
      expect(container.textContent).toContain('XSS Protection')
    })
  })

  describe('Mode Filter', () => {
    it('should filter custom rules by mode', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const selects = container.querySelectorAll('select')
      const modeSelect = selects[1] as HTMLSelectElement

      modeSelect.value = 'block'
      modeSelect.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(container.textContent).toContain('Custom Block Rule')
      expect(container.textContent).not.toContain('Custom Detect Rule')
    })

    it('should filter by detect mode', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const selects = container.querySelectorAll('select')
      const modeSelect = selects[1] as HTMLSelectElement

      modeSelect.value = 'detect'
      modeSelect.dispatchEvent(new Event('change', { bubbles: true }))

      await new Promise((resolve) => setTimeout(resolve, 100))

      expect(container.textContent).toContain('Custom Detect Rule')
      expect(container.textContent).not.toContain('Custom Block Rule')
    })
  })

  describe('Default Rules Section', () => {
    it('should render collapsible default rules section', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Default Rules')
      expect(container.textContent).toContain('Built-in WAF Protection')
    })

    it('should display default rules count', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toMatch(/3 standard protection rules/)
    })

    it('should show "Always Active & Blocking" status', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Always Active & Blocking')
    })
  })

  describe('Action Buttons', () => {
    it('should call onViewDetails when Details button clicked', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      const detailsButton = Array.from(buttons).find((btn) => btn.textContent === 'Details')

      expect(detailsButton).toBeTruthy()

      if (detailsButton) {
        detailsButton.click()
        expect(mockOnViewDetails).toHaveBeenCalled()
        expect(mockOnViewDetails).toHaveBeenCalledWith(mockDefaultRules[0])
      }
    })

    it('should call onEdit when Edit button clicked', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      const editButton = Array.from(buttons).find((btn) => btn.textContent === 'Edit')

      expect(editButton).toBeTruthy()

      if (editButton) {
        editButton.click()
        expect(mockOnEdit).toHaveBeenCalled()
        expect(mockOnEdit).toHaveBeenCalledWith(mockCustomRules[0])
      }
    })

    it('should call onDelete when Delete button clicked', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      const deleteButton = Array.from(buttons).find((btn) => btn.textContent === 'Delete')

      expect(deleteButton).toBeTruthy()

      if (deleteButton) {
        deleteButton.click()
        expect(mockOnDelete).toHaveBeenCalled()
        expect(mockOnDelete).toHaveBeenCalledWith('custom-1')
      }
    })

    it('should call onToggle when status button clicked', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      const statusButton = Array.from(buttons).find((btn) => btn.textContent === 'ENABLED')

      expect(statusButton).toBeTruthy()

      if (statusButton) {
        statusButton.click()
        expect(mockOnToggle).toHaveBeenCalled()
        expect(mockOnToggle).toHaveBeenCalledWith('custom-1')
      }
    })

    it('should disable Edit button for manual block rules', async () => {
      const manualRule = { ...mockCustomRules[2], is_manual_block: true }

      await renderComponent({
        customRules: [manualRule],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      const editButton = Array.from(buttons).find((btn) => btn.textContent === 'Edit')

      expect(editButton).toBeTruthy()
      expect((editButton as HTMLButtonElement).disabled).toBe(true)
    })
  })

  describe('Display Styling', () => {
    it('should display severity badges correctly', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('CRITICAL')
      expect(container.textContent).toContain('HIGH')
      expect(container.textContent).toContain('MEDIUM')
    })

    it('should display DETECT & BLOCK status for default rules', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const detectBlockElements = container.querySelectorAll('*')
      const hasDetectBlock = Array.from(detectBlockElements).some(
        (el) => el.textContent === 'DETECT & BLOCK'
      )
      expect(hasDetectBlock).toBe(true)
    })

    it('should display BLOCK mode for custom block rules', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('BLOCK')
    })

    it('should display DETECT mode for custom detect rules', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('DETECT')
    })

    it('should display ENABLED status', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('ENABLED')
    })

    it('should display DISABLED status', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('DISABLED')
    })
  })

  describe('Edge Cases', () => {
    it('should handle empty arrays', async () => {
      await renderComponent({
        defaultRules: [],
        customRules: [],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('No rules found')
    })

    it('should prefer customRules over rules prop', async () => {
      const differentRules: WAFRule[] = [
        {
          id: 'different',
          name: 'Different Rule',
          description: 'Should not appear',
          type: 'test',
          enabled: true,
        },
      ]

      await renderComponent({
        customRules: mockCustomRules,
        rules: differentRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Custom Block Rule')
      expect(container.textContent).not.toContain('Different Rule')
    })

    it('should use rules prop when customRules is empty', async () => {
      await renderComponent({
        rules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Custom Block Rule')
    })

    it('should handle rules without optional fields', async () => {
      const minimalRule: WAFRule = {
        id: 'minimal',
        name: 'Minimal Rule',
        description: '',
        enabled: true,
      }

      await renderComponent({
        customRules: [minimalRule],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Minimal Rule')
    })

    it('should handle rules with both type and threatType', async () => {
      const mixedRule: WAFRule = {
        id: 'mixed',
        name: 'Mixed Type Rule',
        description: 'Has both fields',
        type: 'sqli',
        threatType: 'xss',
        enabled: true,
      }

      await renderComponent({
        customRules: [mixedRule],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Mixed Type Rule')
    })

    it('should handle rules with both action and mode fields', async () => {
      const mixedModeRule: WAFRule = {
        id: 'mixed-mode',
        name: 'Mixed Mode Rule',
        description: 'Has both action and mode',
        type: 'custom',
        action: 'block',
        mode: 'detect',
        enabled: true,
      }

      await renderComponent({
        customRules: [mixedModeRule],
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      expect(container.textContent).toContain('Mixed Mode Rule')
    })
  })

  describe('Accessibility', () => {
    it('should have accessible form labels', async () => {
      await renderComponent({
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const labels = container.querySelectorAll('label')
      const labelTexts = Array.from(labels).map((label) => label.textContent)

      expect(labelTexts).toContain('Search')
      expect(labelTexts).toContain('Threat Type')
      expect(labelTexts).toContain('Mode')
    })

    it('should have accessible table structure', async () => {
      await renderComponent({
        defaultRules: mockDefaultRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const table = container.querySelector('table')
      expect(table).toBeTruthy()

      const thead = table?.querySelector('thead')
      expect(thead).toBeTruthy()

      const tbody = table?.querySelector('tbody')
      expect(tbody).toBeTruthy()
    })

    it('should have accessible buttons', async () => {
      await renderComponent({
        customRules: mockCustomRules,
        onEdit: mockOnEdit,
        onDelete: mockOnDelete,
        onToggle: mockOnToggle,
        onViewDetails: mockOnViewDetails,
      })

      const buttons = container.querySelectorAll('button')
      expect(buttons.length).toBeGreaterThan(0)

      // All buttons should have text content
      Array.from(buttons).forEach((button) => {
        expect(button.textContent?.trim()).not.toBe('')
      })
    })
  })
})
