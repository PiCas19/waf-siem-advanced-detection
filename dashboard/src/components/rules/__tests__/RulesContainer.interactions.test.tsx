import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import RulesContainer from '../RulesContainer'
import type { WAFRule } from '../../../types/waf'

// Mock dei componenti figli
vi.mock('../AddRule', () => ({
  default: ({ onRuleAdded, onCancel }: any) => (
    <div data-testid="add-rule-view">
      <button onClick={() => onRuleAdded({ id: 'new-1', name: 'New Rule', enabled: true })}>
        Submit Rule
      </button>
      <button onClick={onCancel}>Cancel Add</button>
    </div>
  ),
}))

vi.mock('../RuleEditor', () => ({
  default: ({ rule, onRuleUpdated, onCancel }: any) => (
    <div data-testid="rule-editor-view">
      <span>Editing: {rule.name}</span>
      <button onClick={() => onRuleUpdated({ ...rule, name: 'Updated Rule' })}>
        Save Changes
      </button>
      <button onClick={onCancel}>Cancel Edit</button>
    </div>
  ),
}))

vi.mock('../RulesList', () => ({
  default: ({ defaultRules, customRules, onEdit, onDelete, onToggle, onViewDetails }: any) => (
    <div data-testid="rules-list-view">
      {defaultRules.map((rule: WAFRule) => (
        <div key={rule.id} data-testid={`default-rule-${rule.id}`}>
          <span>{rule.name}</span>
          <button onClick={() => onViewDetails(rule)}>View Default</button>
          <button onClick={() => onDelete(rule.id)}>Delete Default</button>
          <button onClick={() => onToggle(rule.id)}>Toggle Default</button>
        </div>
      ))}
      {customRules.map((rule: WAFRule) => (
        <div key={rule.id} data-testid={`custom-rule-${rule.id}`}>
          <span>{rule.name}</span>
          <button onClick={() => onEdit(rule)}>Edit Custom</button>
          <button onClick={() => onDelete(rule.id)}>Delete Custom</button>
          <button onClick={() => onToggle(rule.id)}>Toggle Custom</button>
          <button onClick={() => onViewDetails(rule)}>View Custom</button>
        </div>
      ))}
    </div>
  ),
}))

vi.mock('../RuleTest', () => ({
  default: ({ rule }: any) => (
    <div data-testid="rule-test">
      Testing rule: {rule?.name || 'Unknown'}
    </div>
  ),
}))

// Mock dei context
const mockShowToast = vi.fn()
vi.mock('@/contexts/SnackbarContext', () => ({
  useToast: () => ({
    showToast: mockShowToast,
  }),
}))

// Mock di localStorage
const localStorageMock = {
  getItem: vi.fn(() => 'fake-token'),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}
global.localStorage = localStorageMock as any

// Mock di fetch
global.fetch = vi.fn()

// Mock di window.confirm
global.confirm = vi.fn()

// Mock di window.dispatchEvent
const mockDispatchEvent = vi.fn()
global.window.dispatchEvent = mockDispatchEvent

describe('RulesContainer - Interactions Coverage', () => {
  const mockDefaultRules = [
    {
      id: 'default-1',
      name: 'SQL Injection Default',
      description: 'Default SQL injection rule',
      type: 'sqli',
      severity: 'CRITICAL',
      enabled: true,
      is_default: true,
    },
  ]

  const mockCustomRules = [
    {
      id: 'custom-1',
      name: 'Custom Rule 1',
      description: 'Custom test rule',
      type: 'custom',
      action: 'block',
      enabled: true,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    ;(global.fetch as any).mockResolvedValue({
      ok: true,
      json: async () => ({
        default_rules: mockDefaultRules,
        custom_rules: { items: mockCustomRules },
      }),
    })
  })

  describe('handleAddRule (LINEA 58-59)', () => {
    it('should add rule to customRules and switch to list view', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      // Switch to add view
      fireEvent.click(screen.getByText('Add Rule'))

      await waitFor(() => {
        expect(screen.getByTestId('add-rule-view')).toBeInTheDocument()
      })

      // LINEA 58-59: Submit new rule
      fireEvent.click(screen.getByText('Submit Rule'))

      // Should return to list view
      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })
    })
  })

  describe('handleRuleUpdated (LINEA 63-65)', () => {
    it('should update rule in customRules and return to list view', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // Click edit on custom rule
      fireEvent.click(screen.getByText('Edit Custom'))

      await waitFor(() => {
        expect(screen.getByTestId('rule-editor-view')).toBeInTheDocument()
      })

      // LINEA 63-65: Save changes
      fireEvent.click(screen.getByText('Save Changes'))

      // Should return to list view
      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })
    })
  })

  describe('handleDeleteRule (LINEA 70-105)', () => {
    it('should prevent deletion of default rules (LINEA 70-74)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 70-74: Try to delete default rule
      fireEvent.click(screen.getByText('Delete Default'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Cannot delete default rules', 'info', 4000)
      })

      // Confirm should not be called
      expect(global.confirm).not.toHaveBeenCalled()
    })

    it('should not delete if user cancels confirm (LINEA 76)', async () => {
      ;(global.confirm as any).mockReturnValue(false)

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // Try to delete custom rule
      fireEvent.click(screen.getByText('Delete Custom'))

      await waitFor(() => {
        expect(global.confirm).toHaveBeenCalled()
      })

      // DELETE API should not be called
      const fetchCalls = (global.fetch as any).mock.calls
      const deleteCalls = fetchCalls.filter((call: any) => call[1]?.method === 'DELETE')
      expect(deleteCalls.length).toBe(0)
    })

    it('should successfully delete custom rule (LINEA 80-91)', async () => {
      ;(global.confirm as any).mockReturnValue(true)
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 80-91: Delete custom rule
      fireEvent.click(screen.getByText('Delete Custom'))

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          '/api/rules/custom-1',
          expect.objectContaining({
            method: 'DELETE',
            headers: expect.objectContaining({
              Authorization: 'Bearer fake-token',
            }),
          })
        )
      })

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Rule deleted successfully', 'success', 4000)
      })
    })

    it('should dispatch statsRefresh event when manual_block_deleted (LINEA 94-99)', async () => {
      ;(global.confirm as any).mockReturnValue(true)
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true, manual_block_deleted: true }),
        })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 94-99: Delete manual block rule
      fireEvent.click(screen.getByText('Delete Custom'))

      await waitFor(() => {
        expect(mockDispatchEvent).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'statsRefresh',
            detail: expect.objectContaining({
              timestamp: expect.any(Number),
            }),
          })
        )
      })
    })

    it('should handle delete error response (LINEA 100-103)', async () => {
      ;(global.confirm as any).mockReturnValue(true)
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockResolvedValueOnce({
          ok: false,
          json: async () => ({ error: 'Rule not found' }),
        })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 100-103: Delete with error response
      fireEvent.click(screen.getByText('Delete Custom'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith(
          'Error deleting rule: Rule not found',
          'error',
          4000
        )
      })
    })

    it('should handle delete network error (LINEA 104-105)', async () => {
      ;(global.confirm as any).mockReturnValue(true)
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockRejectedValueOnce(new Error('Network error'))

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 104-105: Delete with network error
      fireEvent.click(screen.getByText('Delete Custom'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Error deleting rule', 'error', 4000)
      })
    })
  })

  describe('handleToggleRule (LINEA 112-143)', () => {
    it('should prevent toggling default rules (LINEA 112-116)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 112-116: Try to toggle default rule
      fireEvent.click(screen.getByText('Toggle Default'))

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Cannot modify default rules', 'info', 4000)
      })
    })

    it('should successfully toggle custom rule (LINEA 121-140)', async () => {
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ enabled: false }),
        })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 121-140: Toggle custom rule
      fireEvent.click(screen.getByText('Toggle Custom'))

      await waitFor(() => {
        expect(global.fetch).toHaveBeenCalledWith(
          '/api/rules/custom-1/toggle',
          expect.objectContaining({
            method: 'PATCH',
            headers: expect.objectContaining({
              Authorization: 'Bearer fake-token',
            }),
          })
        )
      })
    })

    it('should handle toggle error (LINEA 142-143)', async () => {
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockRejectedValueOnce(new Error('Toggle failed'))

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 142-143: Toggle with error
      fireEvent.click(screen.getByText('Toggle Custom'))

      await waitFor(() => {
        expect(consoleErrorSpy).toHaveBeenCalledWith('Error toggling rule:', expect.any(Error))
      })

      consoleErrorSpy.mockRestore()
    })
  })

  describe('handleEditRule (LINEA 148-150)', () => {
    it('should switch to edit view and set editingRule', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 148-150: Click edit
      fireEvent.click(screen.getByText('Edit Custom'))

      await waitFor(() => {
        expect(screen.getByTestId('rule-editor-view')).toBeInTheDocument()
        expect(screen.getByText('Editing: Custom Rule 1')).toBeInTheDocument()
      })
    })
  })

  describe('handleViewDetails (LINEA 154-155)', () => {
    it('should open details modal with selected rule', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // LINEA 154-155: Click view details
      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // Modal should be visible - check for Description which is only in modal
        expect(screen.getByText('Description')).toBeInTheDocument()
        expect(screen.getByText('Custom test rule')).toBeInTheDocument()
      })
    })
  })

  describe('handleTestRule (LINEA 159-160)', () => {
    it('should open test modal with selected rule', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      // Click view details first to show modal
      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Test')).toBeInTheDocument()
      })

      // LINEA 159-160: Click test button in modal
      fireEvent.click(screen.getByText('Test'))

      await waitFor(() => {
        expect(screen.getByTestId('rule-test')).toBeInTheDocument()
        expect(screen.getByText('Testing rule: Custom Rule 1')).toBeInTheDocument()
      })
    })
  })

  describe('Details Modal Rendering (LINEA 214-373)', () => {
    it('should render modal with manual block indicator (LINEA 229-238)', async () => {
      const manualBlockRule = {
        ...mockCustomRules[0],
        is_manual_block: true,
      }

      ;(global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => ({
          default_rules: mockDefaultRules,
          custom_rules: { items: [manualBlockRule] },
        }),
      })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 229-238: Manual block indicator
        expect(screen.getByText('🔒 Manual Block Rule')).toBeInTheDocument()
      })
    })

    it('should render severity badge (LINEA 260-275)', async () => {
      const ruleWithSeverity = {
        ...mockCustomRules[0],
        severity: 'CRITICAL',
      }

      ;(global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => ({
          default_rules: mockDefaultRules,
          custom_rules: { items: [ruleWithSeverity] },
        }),
      })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 260-275: Severity badge
        expect(screen.getByText('CRITICAL')).toBeInTheDocument()
      })
    })

    it('should render examples list (LINEA 277-291)', async () => {
      const ruleWithExamples = {
        ...mockCustomRules[0],
        examples: ['ex1', 'ex2', 'ex3', 'ex4', 'ex5'],
      }

      ;(global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => ({
          default_rules: mockDefaultRules,
          custom_rules: { items: [ruleWithExamples] },
        }),
      })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 277-291: Examples list (max 3 shown)
        expect(screen.getByText(/ex1/)).toBeInTheDocument()
        expect(screen.getByText(/\+ 2 more examples/)).toBeInTheDocument()
      })
    })

    it('should render pattern (LINEA 293-300)', async () => {
      const ruleWithPattern = {
        ...mockCustomRules[0],
        pattern: '.*test.*',
      }

      ;(global.fetch as any).mockResolvedValue({
        ok: true,
        json: async () => ({
          default_rules: mockDefaultRules,
          custom_rules: { items: [ruleWithPattern] },
        }),
      })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 293-300: Pattern display
        expect(screen.getByText('.*test.*')).toBeInTheDocument()
      })
    })

    it('should show timestamps for custom rules (LINEA 303-318)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 303-318: Timestamps for custom rules
        expect(screen.getByText('Created')).toBeInTheDocument()
        expect(screen.getByText('Last Updated')).toBeInTheDocument()
      })
    })

    it('should show edit/delete buttons for custom rules (LINEA 330-349)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        // LINEA 332-348: Edit and Delete buttons
        expect(screen.getAllByText('Edit')[0]).toBeInTheDocument()
        expect(screen.getAllByText('Delete')[0]).toBeInTheDocument()
      })
    })

    it('should show built-in message for default rules (LINEA 350-354)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Default'))

      await waitFor(() => {
        // LINEA 350-354: Built-in rule message
        expect(
          screen.getByText('This is a built-in rule and cannot be edited or deleted')
        ).toBeInTheDocument()
      })
    })

    it('should close modal when clicking close button (LINEA 364-369)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument()
      })

      // LINEA 364-369: Click close button
      const closeButtons = screen.getAllByText('Close')
      fireEvent.click(closeButtons[0])

      await waitFor(() => {
        expect(screen.queryByText('Description')).not.toBeInTheDocument()
      })
    })

    it('should close modal with X button (LINEA 220-224)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument()
      })

      // LINEA 220-224: Click X button
      const xButtons = screen.getAllByText('×')
      fireEvent.click(xButtons[0])

      await waitFor(() => {
        expect(screen.queryByText('Description')).not.toBeInTheDocument()
      })
    })
  })

  describe('Test Modal Rendering (LINEA 376-399)', () => {
    it('should render test modal with RuleTest component (LINEA 376-399)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Test')).toBeInTheDocument()
      })

      // LINEA 376-399: Open test modal
      fireEvent.click(screen.getByText('Test'))

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument()
        expect(screen.getByTestId('rule-test')).toBeInTheDocument()
      })
    })

    it('should close test modal (LINEA 390-395)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Test')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Test'))

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument()
      })

      // LINEA 390-395: Close test modal
      const closeButtons = screen.getAllByText('Close')
      fireEvent.click(closeButtons[closeButtons.length - 1])

      await waitFor(() => {
        expect(screen.queryByText('Test Rule')).not.toBeInTheDocument()
      })
    })

    it('should close test modal with X button (LINEA 381-386)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))
      fireEvent.click(screen.getByText('Test'))

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument()
      })

      // LINEA 381-386: Close with X
      const xButtons = screen.getAllByText('×')
      fireEvent.click(xButtons[xButtons.length - 1])

      await waitFor(() => {
        expect(screen.queryByText('Test Rule')).not.toBeInTheDocument()
      })
    })
  })

  describe('Edit from Details Modal (LINEA 333-336)', () => {
    it('should open edit view from details modal', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument()
      })

      // LINEA 333-336: Click edit in modal
      const editButtons = screen.getAllByText('Edit')
      fireEvent.click(editButtons[0])

      await waitFor(() => {
        expect(screen.getByTestId('rule-editor-view')).toBeInTheDocument()
        // Modal should be closed
        expect(screen.queryByText('Description')).not.toBeInTheDocument()
      })
    })
  })

  describe('Delete from Details Modal (LINEA 342-348)', () => {
    it('should delete rule from details modal', async () => {
      ;(global.confirm as any).mockReturnValue(true)
      ;(global.fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({
            default_rules: mockDefaultRules,
            custom_rules: { items: mockCustomRules },
          }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        })

      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument()
      })

      // LINEA 342-348: Click delete in modal
      const deleteButtons = screen.getAllByText('Delete')
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(mockShowToast).toHaveBeenCalledWith('Rule deleted successfully', 'success', 4000)
      })
    })
  })

  describe('Test from Details Modal (LINEA 356-359)', () => {
    it('should open test modal from details modal and close details', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('View Custom'))

      await waitFor(() => {
        expect(screen.getByText('Description')).toBeInTheDocument()
      })

      // LINEA 356-359: Click test in details modal
      fireEvent.click(screen.getByText('Test'))

      await waitFor(() => {
        expect(screen.getByText('Test Rule')).toBeInTheDocument()
        // Details modal should be closed - Description is only in details modal
        expect(screen.queryByText('Description')).not.toBeInTheDocument()
      })
    })
  })

  describe('Add View Navigation (LINEA 182-187)', () => {
    it('should show Add Rule button in list view (LINEA 171-178)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        // LINEA 171-178: Add Rule button visible in list view
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })
    })

    it('should render AddRule component when view is add (LINEA 182-187)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      // LINEA 182-187: Switch to add view
      fireEvent.click(screen.getByText('Add Rule'))

      await waitFor(() => {
        expect(screen.getByTestId('add-rule-view')).toBeInTheDocument()
      })
    })
  })

  describe('Edit View Navigation (LINEA 190-199)', () => {
    it('should render RuleEditor when editingRule is set (LINEA 190-199)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Edit Custom'))

      await waitFor(() => {
        // LINEA 190-199: RuleEditor rendered with editingRule
        expect(screen.getByTestId('rule-editor-view')).toBeInTheDocument()
        expect(screen.getByText('Editing: Custom Rule 1')).toBeInTheDocument()
      })
    })

    it('should reset editingRule to null on cancel (LINEA 194-197)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Edit Custom'))

      await waitFor(() => {
        expect(screen.getByTestId('rule-editor-view')).toBeInTheDocument()
      })

      // LINEA 194-197: Cancel edit
      fireEvent.click(screen.getByText('Cancel Edit'))

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
        expect(screen.queryByTestId('rule-editor-view')).not.toBeInTheDocument()
      })
    })
  })

  describe('Cancel Add Navigation (LINEA 185)', () => {
    it('should return to list view when canceling add (LINEA 185)', async () => {
      render(<RulesContainer />)

      await waitFor(() => {
        expect(screen.getByText('Add Rule')).toBeInTheDocument()
      })

      fireEvent.click(screen.getByText('Add Rule'))

      await waitFor(() => {
        expect(screen.getByTestId('add-rule-view')).toBeInTheDocument()
      })

      // LINEA 185: Cancel add
      fireEvent.click(screen.getByText('Cancel Add'))

      await waitFor(() => {
        expect(screen.getByTestId('rules-list-view')).toBeInTheDocument()
      })
    })
  })
})
