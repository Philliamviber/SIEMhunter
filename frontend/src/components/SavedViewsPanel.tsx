/**
 * SavedViewsPanel — reusable panel for per-page named saved views.
 *
 * Renders a compact "Save View" input and a list of existing saved views for
 * the current page.  The parent supplies the current filter state and a
 * callback to apply a loaded view; this component owns only the save/delete
 * interactions against the backend.
 *
 * Identity scoping is enforced server-side; this component never passes an
 * owner field to the API.
 */
import { useState } from 'react';
import type { SavedViewPage } from '../types/api';
import { useSavedViews, useUpsertSavedView, useDeleteSavedView } from '../hooks/useApi';

interface Props {
  page: SavedViewPage;
  currentFilters: Record<string, unknown>;
  onLoad: (filters: Record<string, unknown>) => void;
}

export function SavedViewsPanel({ page, currentFilters, onLoad }: Props) {
  const [saveInputVisible, setSaveInputVisible] = useState(false);
  const [name, setName] = useState('');

  const { data, isLoading } = useSavedViews(page);
  const upsert = useUpsertSavedView(page);
  const remove = useDeleteSavedView(page);

  const views = data?.views ?? [];

  function handleSave() {
    const trimmed = name.trim();
    if (!trimmed) return;
    upsert.mutate(
      { name: trimmed, page, filters: currentFilters },
      {
        onSuccess: () => {
          setName('');
          setSaveInputVisible(false);
        },
      },
    );
  }

  function handleDelete(viewName: string) {
    remove.mutate({ page, name: viewName });
  }

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-gray-300">Saved Views</span>
        <button
          onClick={() => setSaveInputVisible((v) => !v)}
          className="text-xs text-cyan-400 hover:text-cyan-200 transition-colors"
          aria-label="Save current view"
        >
          {saveInputVisible ? 'Cancel' : '+ Save'}
        </button>
      </div>

      {saveInputVisible && (
        <div className="flex gap-1.5 mb-2">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleSave(); }}
            placeholder="View name…"
            maxLength={100}
            autoFocus
            className="flex-1 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-white text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
          <button
            onClick={handleSave}
            disabled={!name.trim() || upsert.isPending}
            className="px-2 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Save
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="text-xs text-gray-500 py-1">Loading…</div>
      ) : views.length === 0 ? (
        <div className="text-xs text-gray-600 py-1">No saved views</div>
      ) : (
        <ul className="space-y-1" role="list" aria-label="Saved views">
          {views.map((view) => (
            <li
              key={view.name}
              className="flex items-center justify-between gap-1 group"
            >
              <button
                onClick={() => onLoad(view.filters)}
                className="flex-1 text-left text-xs text-gray-300 hover:text-white truncate py-0.5 transition-colors"
                title={view.name}
                aria-label={`Load saved view: ${view.name}`}
              >
                {view.name}
              </button>
              <button
                onClick={() => handleDelete(view.name)}
                disabled={remove.isPending}
                className="text-gray-600 hover:text-red-400 text-xs opacity-0 group-hover:opacity-100 transition-all disabled:cursor-not-allowed flex-shrink-0"
                aria-label={`Delete saved view: ${view.name}`}
                title="Delete"
              >
                ✕
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
