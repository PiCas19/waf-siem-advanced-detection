import { describe, it, expect, vi, beforeEach, afterEach, Mock } from 'vitest';
import { render, screen } from '../../../test/test-utils';
import Snackbar, { SnackbarMessage } from '../Snackbar';
import { userEvent } from '@testing-library/user-event';

describe('Snackbar', () => {
  let mockOnClose: Mock<(id: string) => void>;

  beforeEach(() => {
    mockOnClose = vi.fn(); // vi.fn() già restituisce Mock, non serve ReturnType
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  const createMessage = (
    overrides?: Partial<SnackbarMessage>
  ): SnackbarMessage => ({
    id: 'test-id',
    type: 'success',
    message: 'Test message',
    ...overrides,
  });

  describe('rendering', () => {
    it('should render success snackbar with correct styling', () => {
      const message = createMessage({ type: 'success' });
      const { container } = render(
        <Snackbar message={message} onClose={mockOnClose} />
      );

      expect(screen.getByText('Test message')).toBeInTheDocument();
      expect(screen.getByRole('alert')).toBeInTheDocument();
      expect(container.firstChild).toHaveClass('bg-emerald-600', 'border-emerald-500');
    });

    it('should render error snackbar with correct styling', () => {
      const message = createMessage({ type: 'error' });
      const { container } = render(
        <Snackbar message={message} onClose={mockOnClose} />
      );

      expect(container.firstChild).toHaveClass('bg-red-600', 'border-red-500');
    });

    it('should render warning snackbar with correct styling', () => {
      const message = createMessage({ type: 'warning' });
      const { container } = render(
        <Snackbar message={message} onClose={mockOnClose} />
      );

      expect(container.firstChild).toHaveClass('bg-amber-600', 'border-amber-500');
    });

    it('should render info snackbar with correct styling', () => {
      const message = createMessage({ type: 'info' });
      const { container } = render(
        <Snackbar message={message} onClose={mockOnClose} />
      );

      expect(container.firstChild).toHaveClass('bg-blue-600', 'border-blue-500');
    });

    it('should render the message text', () => {
      const message = createMessage({ message: 'Custom notification text' });
      render(<Snackbar message={message} onClose={mockOnClose} />);

      expect(screen.getByText('Custom notification text')).toBeInTheDocument();
    });

    it('should render close button', () => {
      const message = createMessage();
      render(<Snackbar message={message} onClose={mockOnClose} />);

      const closeButton = screen.getByRole('button', { name: /close notification/i });
      expect(closeButton).toBeInTheDocument();
    });
  });

  describe('interactions', () => {
    it('should call onClose when close button is clicked', async () => {
      vi.useRealTimers(); // Use real timers for user interaction
      const user = userEvent.setup();
      const message = createMessage();
      render(<Snackbar message={message} onClose={mockOnClose} />);

      const closeButton = screen.getByRole('button', { name: /close notification/i });
      await user.click(closeButton);

      expect(mockOnClose).toHaveBeenCalledWith('test-id');
      expect(mockOnClose).toHaveBeenCalledTimes(1);
      vi.useFakeTimers(); // Restore fake timers
    });

    it('should not auto-close when duration is not set', () => {
      const message = createMessage({ duration: undefined });
      render(<Snackbar message={message} onClose={mockOnClose} />);

      vi.advanceTimersByTime(10000);

      expect(mockOnClose).not.toHaveBeenCalled();
    });

    it('should auto-close after duration', () => {
      const message = createMessage({ duration: 3000 });
      render(<Snackbar message={message} onClose={mockOnClose} />);

      expect(mockOnClose).not.toHaveBeenCalled();

      vi.advanceTimersByTime(3000);

      expect(mockOnClose).toHaveBeenCalledWith('test-id');
    });

    it('should not auto-close when duration is 0', () => {
      const message = createMessage({ duration: 0 });
      render(<Snackbar message={message} onClose={mockOnClose} />);

      vi.advanceTimersByTime(10000);

      expect(mockOnClose).not.toHaveBeenCalled();
    });

    it('should clear timeout when unmounted before duration', () => {
      const message = createMessage({ duration: 5000 });
      const { unmount } = render(
        <Snackbar message={message} onClose={mockOnClose} />
      );

      vi.advanceTimersByTime(2000);
      unmount();
      vi.advanceTimersByTime(5000);

      expect(mockOnClose).not.toHaveBeenCalled();
    });
  });

  describe('accessibility', () => {
    it('should have role="alert"', () => {
      const message = createMessage();
      render(<Snackbar message={message} onClose={mockOnClose} />);

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });

    it('should have aria-label on close button', () => {
      const message = createMessage();
      render(<Snackbar message={message} onClose={mockOnClose} />);

      const closeButton = screen.getByLabelText('Close notification');
      expect(closeButton).toBeInTheDocument();
    });
  });

  describe('multiple snackbars', () => {
    it('should handle different message IDs', async () => {
      vi.useRealTimers(); // Use real timers for user interaction
      const user = userEvent.setup();
      const message1 = createMessage({ id: 'msg-1', message: 'Message 1' });
      const message2 = createMessage({ id: 'msg-2', message: 'Message 2' });

      const { rerender } = render(
        <Snackbar message={message1} onClose={mockOnClose} />
      );
      const closeButton1 = screen.getByRole('button', { name: /close notification/i });
      await user.click(closeButton1);
      expect(mockOnClose).toHaveBeenCalledWith('msg-1');

      mockOnClose.mockClear();
      rerender(<Snackbar message={message2} onClose={mockOnClose} />);
      const closeButton2 = screen.getByRole('button', { name: /close notification/i });
      await user.click(closeButton2);
      expect(mockOnClose).toHaveBeenCalledWith('msg-2');
      vi.useFakeTimers(); // Restore fake timers
    });
  });
});