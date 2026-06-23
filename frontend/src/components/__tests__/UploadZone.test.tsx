/**
 * UploadZone tests — multi-file, progress, cancel, retry, and query invalidation.
 */
import { describe, it, expect, vi, beforeEach, type Mock } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { UploadZone } from '../UploadZone';
import { ToastProvider } from '../ToastProvider';

// ── Mock uploadFileWithProgress ───────────────────────────────────────────────

vi.mock('../../api/client', () => ({
  uploadFileWithProgress: vi.fn(),
}));

import { uploadFileWithProgress } from '../../api/client';
const mockUpload = uploadFileWithProgress as Mock;

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeFile(name = 'test.log', size = 1024): File {
  return new File(['x'.repeat(size)], name, { type: 'text/plain' });
}

const FAKE_RESULT = {
  filename: 'test.log',
  provenance_tag: 'manual-upload',
  events_parsed: 10,
  events_written: 10,
  events_unmapped: 0,
  error_count: 0,
  status: 'success' as const,
};

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ToastProvider>{children}</ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('UploadZone', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the drop zone', () => {
    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    expect(screen.getByText(/drag and drop files here/i)).toBeTruthy();
  });

  it('rejects a file with a disallowed extension and shows an error', async () => {
    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('evil.exe')] } });
    });
    expect(screen.getByText(/file type not supported/i)).toBeTruthy();
    expect(screen.queryByText(/upload/i)).toBeFalsy(); // no upload button
  });

  it('rejects a file exceeding 100 MiB', async () => {
    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    // Avoid allocating 101 MB — mock the size property instead.
    const bigFile = makeFile('big.log', 1);
    Object.defineProperty(bigFile, 'size', { value: 101 * 1024 * 1024 });
    await act(async () => {
      fireEvent.change(input, { target: { files: [bigFile] } });
    });
    expect(screen.getByText(/too large/i)).toBeTruthy();
  });

  it('adds multiple files and shows Upload N Files button', async () => {
    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;
    await act(async () => {
      fireEvent.change(input, {
        target: { files: [makeFile('a.log'), makeFile('b.log')] },
      });
    });
    expect(screen.getByText('a.log')).toBeTruthy();
    expect(screen.getByText('b.log')).toBeTruthy();
    expect(screen.getByRole('button', { name: /upload 2 files/i })).toBeTruthy();
  });

  it('shows progress bar during upload and calls onUploadComplete on success', async () => {
    let resolveUpload!: (r: typeof FAKE_RESULT) => void;
    mockUpload.mockImplementation(
      (_file: File, _mode: string, _id: string | undefined, onProgress: (n: number) => void, _signal: AbortSignal) => {
        return new Promise<typeof FAKE_RESULT>((res) => {
          onProgress(50);
          resolveUpload = res;
        });
      },
    );

    const onComplete = vi.fn();
    render(<UploadZone onUploadComplete={onComplete} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('data.log')] } });
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId('upload-submit-btn'));
    });

    // Progress bar should be visible
    await waitFor(() => {
      expect(screen.getByRole('progressbar')).toBeTruthy();
    });

    // Resolve the upload
    await act(async () => {
      resolveUpload(FAKE_RESULT);
    });

    await waitFor(() => {
      expect(screen.getByText(/uploaded successfully/i)).toBeTruthy();
    });
    expect(onComplete).toHaveBeenCalledWith(FAKE_RESULT);
  });

  it('cancel button aborts an in-flight upload', async () => {
    let capturedSignal!: AbortSignal;
    mockUpload.mockImplementation(
      (_file: File, _mode: string, _id: string | undefined, _onProgress: (n: number) => void, signal: AbortSignal) => {
        capturedSignal = signal;
        return new Promise<typeof FAKE_RESULT>((_res, rej) => {
          signal.addEventListener('abort', () =>
            rej(new DOMException('Upload cancelled', 'AbortError')),
          );
        });
      },
    );

    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('data.log')] } });
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('upload-submit-btn'));
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /cancel/i })).toBeTruthy();
    });

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
    });

    await waitFor(() => {
      expect(screen.getByText(/cancelled/i)).toBeTruthy();
    });

    expect(capturedSignal.aborted).toBe(true);
  });

  it('shows error state and retry button when upload fails', async () => {
    mockUpload.mockRejectedValueOnce(new Error('Network error during upload'));

    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('data.log')] } });
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('upload-submit-btn'));
    });

    await waitFor(() => {
      expect(screen.getByText(/network error during upload/i)).toBeTruthy();
      expect(screen.getByRole('button', { name: /retry/i })).toBeTruthy();
    });
  });

  it('removes a file when the × button is clicked', async () => {
    render(<UploadZone onUploadComplete={vi.fn()} />, { wrapper });
    const input = document.querySelector('input[type="file"]') as HTMLInputElement;

    await act(async () => {
      fireEvent.change(input, { target: { files: [makeFile('a.log')] } });
    });
    expect(screen.getByText('a.log')).toBeTruthy();

    const removeBtn = screen.getByRole('button', { name: /remove a\.log/i });
    await act(async () => {
      fireEvent.click(removeBtn);
    });
    expect(screen.queryByText('a.log')).toBeNull();
  });
});
