/**
 * UploadZone — drag-and-drop / click-to-pick file upload component.
 *
 * Security notes (MUST 7):
 *  - All displayed values (file name, error messages) are plain React text
 *    nodes. No dangerouslySetInnerHTML is used anywhere in this file.
 *  - Client-side size check is UX-only; the server enforces the hard limit.
 *  - .evtx files are rejected client-side with a guidance message (AC #7).
 */
import { useRef, useState, useCallback, type DragEvent, type KeyboardEvent } from 'react';
import { uploadFile } from '../api/client';
import type { UploadMode, UploadResponse } from '../types/api';

const UPLOAD_MAX_FILE_SIZE_MB = 100;
const ALLOWED_EXTENSIONS = ['.json', '.jsonl', '.csv', '.log', '.txt'];
const EVTX_GUIDANCE =
  'For .evtx files, convert to JSON first using EvtxECmd or similar tool.';

interface Props {
  onUploadComplete: (result: UploadResponse) => void;
  incidentId?: string;
  mode?: UploadMode;
}

export function UploadZone({ onUploadComplete, incidentId, mode = 'global' }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // ── File validation ───────────────────────────────────────────────────────

  function validateFile(file: File): string | null {
    const name = file.name.toLowerCase();

    // .evtx guidance (AC #7)
    if (name.endsWith('.evtx')) {
      return EVTX_GUIDANCE;
    }

    // Extension check
    const hasAllowedExt = ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext));
    if (!hasAllowedExt) {
      return (
        `File type not supported. Allowed: ${ALLOWED_EXTENSIONS.join(' ')}. ` +
        EVTX_GUIDANCE
      );
    }

    // Client-side size check (UX only — server enforces too)
    const maxBytes = UPLOAD_MAX_FILE_SIZE_MB * 1024 * 1024;
    if (file.size > maxBytes) {
      return `File is too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum allowed size is ${UPLOAD_MAX_FILE_SIZE_MB} MB.`;
    }

    return null;
  }

  function handleFileChosen(file: File) {
    setErrorMessage(null);
    const err = validateFile(file);
    if (err) {
      setErrorMessage(err);
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
  }

  // ── Drag handlers ─────────────────────────────────────────────────────────

  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileChosen(file);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Keyboard accessibility ────────────────────────────────────────────────

  function handleKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      inputRef.current?.click();
    }
  }

  // ── Upload action ─────────────────────────────────────────────────────────

  async function handleUpload() {
    if (!selectedFile) return;
    setUploading(true);
    setErrorMessage(null);
    try {
      const result = await uploadFile(selectedFile, mode, incidentId);
      setSelectedFile(null);
      onUploadComplete(result);
    } catch (err) {
      // Show error message as plain text — no HTML injection possible (MUST 7)
      const message = err instanceof Error ? err.message : 'Upload failed';
      setErrorMessage(message);
    } finally {
      setUploading(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────

  const zoneClasses = [
    'border-2 border-dashed rounded-lg p-8 text-center cursor-pointer',
    'transition-colors duration-150 outline-none',
    isDragOver
      ? 'border-purple-400 bg-purple-900/20'
      : 'border-gray-700 bg-gray-900 hover:border-gray-500',
  ].join(' ');

  return (
    <div className="space-y-3">
      {/* Hidden file input */}
      <input
        ref={inputRef}
        type="file"
        className="hidden"
        accept={ALLOWED_EXTENSIONS.join(',')}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (file) handleFileChosen(file);
          // Reset input so the same file can be re-selected after clearing
          e.target.value = '';
        }}
        aria-hidden="true"
      />

      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload file — click or drag and drop"
        className={zoneClasses}
        onClick={() => inputRef.current?.click()}
        onDragEnter={handleDragEnter}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onKeyDown={handleKeyDown}
      >
        {selectedFile ? (
          <div className="space-y-1">
            <div className="text-white font-medium text-sm">{selectedFile.name}</div>
            <div className="text-gray-400 text-xs">
              {(selectedFile.size / 1024).toFixed(1)} KB
            </div>
            <div className="text-gray-500 text-xs mt-1">
              Click or drag a different file to replace
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="text-gray-300 text-sm font-medium">
              Drag and drop a file here, or click to browse
            </div>
            <div className="text-gray-500 text-xs">
              Allowed: {ALLOWED_EXTENSIONS.join('  ')}
            </div>
            <div className="text-gray-500 text-xs">
              Maximum size: {UPLOAD_MAX_FILE_SIZE_MB} MB
            </div>
            <div className="text-gray-600 text-xs mt-1">{EVTX_GUIDANCE}</div>
          </div>
        )}
      </div>

      {/* Error message — plain text node, no innerHTML (MUST 7) */}
      {errorMessage && (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg px-4 py-3 text-red-400 text-sm">
          {errorMessage}
        </div>
      )}

      {/* Upload button — only shown after a valid file is selected */}
      {selectedFile && !uploading && (
        <button
          type="button"
          onClick={handleUpload}
          className="w-full bg-purple-600 hover:bg-purple-500 text-white font-medium text-sm rounded-lg px-4 py-2 transition-colors duration-150"
        >
          Upload
        </button>
      )}

      {/* Uploading spinner */}
      {uploading && (
        <div className="flex items-center justify-center gap-2 py-2 text-gray-400 text-sm">
          <svg
            className="animate-spin h-4 w-4 text-purple-400"
            xmlns="http://www.w3.org/2000/svg"
            fill="none"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          Uploading...
        </div>
      )}
    </div>
  );
}
