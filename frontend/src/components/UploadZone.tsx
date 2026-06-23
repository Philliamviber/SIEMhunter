/**
 * UploadZone — drag-and-drop / click-to-pick multi-file upload component.
 *
 * Security notes (MUST 7):
 *  - All displayed values (file names, error messages) are plain React text
 *    nodes. No dangerouslySetInnerHTML is used anywhere in this file.
 *  - Client-side size/extension checks are UX-only; the server enforces limits.
 *  - .evtx files are rejected client-side with guidance (AC #7).
 */
import { useRef, useState, useCallback, type DragEvent, type KeyboardEvent } from 'react';
import { uploadFileWithProgress } from '../api/client';
import type { UploadMode, UploadResponse } from '../types/api';

const UPLOAD_MAX_FILE_SIZE_MB = 100;
const ALLOWED_EXTENSIONS = ['.json', '.jsonl', '.csv', '.log', '.txt'];
const EVTX_GUIDANCE =
  'For .evtx files, convert to JSON first using EvtxECmd or similar tool.';

type FileStatus = 'pending' | 'uploading' | 'done' | 'error' | 'cancelled';

interface FileItem {
  id: string;
  file: File;
  status: FileStatus;
  progress: number;
  error?: string;
  result?: UploadResponse;
  abortCtrl?: AbortController;
}

interface Props {
  onUploadComplete: (result: UploadResponse) => void;
  incidentId?: string;
  mode?: UploadMode;
}

function validateFile(file: File): string | null {
  const name = file.name.toLowerCase();
  if (name.endsWith('.evtx')) return EVTX_GUIDANCE;
  const hasAllowedExt = ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext));
  if (!hasAllowedExt) {
    return (
      `File type not supported. Allowed: ${ALLOWED_EXTENSIONS.join(' ')}. ` +
      EVTX_GUIDANCE
    );
  }
  const maxBytes = UPLOAD_MAX_FILE_SIZE_MB * 1024 * 1024;
  if (file.size > maxBytes) {
    return `File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum allowed size is ${UPLOAD_MAX_FILE_SIZE_MB} MB.`;
  }
  return null;
}

export function UploadZone({ onUploadComplete, incidentId, mode = 'global' }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [files, setFiles] = useState<FileItem[]>([]);
  const [isDragOver, setIsDragOver] = useState(false);

  // ── File ingestion ────────────────────────────────────────────────────────

  function addFiles(incoming: File[]) {
    const items: FileItem[] = incoming.map((file) => {
      const err = validateFile(file);
      return {
        id: crypto.randomUUID(),
        file,
        status: err ? 'error' : 'pending',
        progress: 0,
        error: err ?? undefined,
      };
    });
    setFiles((prev) => [...prev, ...items]);
  }

  // ── Drag handlers ─────────────────────────────────────────────────────────

  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); e.stopPropagation(); setIsDragOver(true);
  }, []);

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); e.stopPropagation(); setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); e.stopPropagation(); setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault(); e.stopPropagation(); setIsDragOver(false);
    const dropped = Array.from(e.dataTransfer.files);
    if (dropped.length > 0) addFiles(dropped);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Keyboard accessibility ────────────────────────────────────────────────

  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      inputRef.current?.click();
    }
  }

  // ── Per-file upload ───────────────────────────────────────────────────────

  async function startUpload(item: FileItem) {
    const abortCtrl = new AbortController();
    setFiles((prev) =>
      prev.map((f) =>
        f.id === item.id
          ? { ...f, status: 'uploading', progress: 0, error: undefined, abortCtrl }
          : f,
      ),
    );
    try {
      const result = await uploadFileWithProgress(
        item.file,
        mode,
        incidentId,
        (pct) =>
          setFiles((prev) =>
            prev.map((f) => (f.id === item.id ? { ...f, progress: pct } : f)),
          ),
        abortCtrl.signal,
      );
      setFiles((prev) =>
        prev.map((f) =>
          f.id === item.id
            ? { ...f, status: 'done', progress: 100, result, abortCtrl: undefined }
            : f,
        ),
      );
      onUploadComplete(result);
    } catch (err) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        setFiles((prev) =>
          prev.map((f) =>
            f.id === item.id
              ? { ...f, status: 'cancelled', progress: 0, abortCtrl: undefined }
              : f,
          ),
        );
      } else {
        const message = err instanceof Error ? err.message : 'Upload failed';
        setFiles((prev) =>
          prev.map((f) =>
            f.id === item.id
              ? { ...f, status: 'error', error: message, abortCtrl: undefined }
              : f,
          ),
        );
      }
    }
  }

  function handleUploadAll() {
    const pending = files.filter((f) => f.status === 'pending');
    pending.forEach((item) => void startUpload(item));
  }

  function handleCancel(item: FileItem) {
    item.abortCtrl?.abort();
  }

  function handleRetry(item: FileItem) {
    void startUpload(item);
  }

  function handleRemove(id: string) {
    setFiles((prev) => prev.filter((f) => f.id !== id));
  }

  // ── Derived state ─────────────────────────────────────────────────────────

  const hasPending = files.some((f) => f.status === 'pending');
  const hasAny = files.length > 0;

  // ── Render ────────────────────────────────────────────────────────────────

  const zoneClasses = [
    'border-2 border-dashed rounded-lg p-8 text-center cursor-pointer',
    'transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-purple-400',
    isDragOver
      ? 'border-purple-400 bg-purple-900/20'
      : 'border-gray-700 bg-gray-900 hover:border-gray-500',
  ].join(' ');

  return (
    <div className="space-y-3">
      {/* Hidden multi-file input */}
      <input
        ref={inputRef}
        type="file"
        multiple
        className="hidden"
        accept={ALLOWED_EXTENSIONS.join(',')}
        onChange={(e) => {
          const picked = Array.from(e.target.files ?? []);
          if (picked.length > 0) addFiles(picked);
          e.target.value = '';
        }}
        aria-hidden="true"
      />

      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload files — click or drag and drop"
        className={zoneClasses}
        onClick={() => inputRef.current?.click()}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onKeyDown={handleKeyDown}
      >
        <div className="space-y-2">
          <div className="text-gray-300 text-sm font-medium">
            Drag and drop files here, or click to browse
          </div>
          <div className="text-gray-500 text-xs">
            Allowed: {ALLOWED_EXTENSIONS.join('  ')}
          </div>
          <div className="text-gray-500 text-xs">
            Maximum size per file: {UPLOAD_MAX_FILE_SIZE_MB} MB
          </div>
          <div className="text-gray-600 text-xs mt-1">{EVTX_GUIDANCE}</div>
        </div>
      </div>

      {/* Per-file status list */}
      {hasAny && (
        <ul className="space-y-2">
          {files.map((item) => (
            <li
              key={item.id}
              className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3 space-y-2"
            >
              {/* File name + remove */}
              <div className="flex items-center justify-between gap-2">
                <span className="text-white text-sm font-medium truncate flex-1">
                  {item.file.name}
                </span>
                <span className="text-gray-500 text-xs shrink-0">
                  {(item.file.size / 1024).toFixed(1)} KB
                </span>
                {(item.status === 'pending' ||
                  item.status === 'done' ||
                  item.status === 'error' ||
                  item.status === 'cancelled') && (
                  <button
                    type="button"
                    onClick={() => handleRemove(item.id)}
                    aria-label={`Remove ${item.file.name}`}
                    className="text-gray-600 hover:text-gray-300 text-base leading-none ml-1"
                  >
                    ×
                  </button>
                )}
              </div>

              {/* Progress bar (uploading) */}
              {item.status === 'uploading' && (
                <div className="space-y-1">
                  <div className="w-full bg-gray-800 rounded-full h-1.5">
                    <div
                      className="bg-purple-500 h-1.5 rounded-full transition-all duration-150"
                      style={{ width: `${item.progress}%` }}
                      role="progressbar"
                      aria-valuenow={item.progress}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-label={`${item.file.name} upload progress`}
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400 text-xs">{item.progress}%</span>
                    <button
                      type="button"
                      onClick={() => handleCancel(item)}
                      className="text-xs text-red-400 hover:text-red-300"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Done */}
              {item.status === 'done' && (
                <span className="text-green-400 text-xs">Uploaded successfully</span>
              )}

              {/* Error */}
              {item.status === 'error' && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-red-400 text-xs flex-1">{item.error}</span>
                  <button
                    type="button"
                    onClick={() => handleRetry(item)}
                    className="text-xs text-purple-400 hover:text-purple-300 shrink-0"
                  >
                    Retry
                  </button>
                </div>
              )}

              {/* Cancelled */}
              {item.status === 'cancelled' && (
                <div className="flex items-center justify-between gap-2">
                  <span className="text-gray-500 text-xs">Cancelled</span>
                  <button
                    type="button"
                    onClick={() => handleRetry(item)}
                    className="text-xs text-purple-400 hover:text-purple-300"
                  >
                    Retry
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}

      {/* Upload All button */}
      {hasPending && (
        <button
          type="button"
          data-testid="upload-submit-btn"
          onClick={handleUploadAll}
          className="w-full bg-purple-600 hover:bg-purple-500 text-white font-medium text-sm rounded-lg px-4 py-2 transition-colors duration-150"
        >
          {files.filter((f) => f.status === 'pending').length === 1
            ? 'Upload File'
            : `Upload ${files.filter((f) => f.status === 'pending').length} Files`}
        </button>
      )}
    </div>
  );
}
