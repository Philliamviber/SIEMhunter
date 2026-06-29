import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSavedViews } from '../hooks/useApi';

interface PaletteItem {
  id: string;
  label: string;
  sublabel?: string;
  category: 'page' | 'view' | 'action';
  onSelect: () => void;
}

const PAGE_DESTINATIONS = [
  { label: 'Overview', path: '/' },
  { label: 'Events', path: '/events' },
  { label: 'Detections', path: '/detections' },
  { label: 'Rules', path: '/rules' },
  { label: 'Ingestion', path: '/ingestion' },
  { label: 'Health', path: '/health' },
  { label: 'Query Console', path: '/query' },
  { label: 'Categories', path: '/categories' },
  { label: 'Incidents', path: '/incidents' },
  { label: 'Correlation', path: '/correlation' },
];

function fuzzyMatch(query: string, target: string): boolean {
  if (!query) return true;
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  let qi = 0;
  for (let i = 0; i < t.length && qi < q.length; i++) {
    if (t[i] === q[qi]) qi++;
  }
  return qi === q.length;
}

interface Props {
  open: boolean;
  onClose: () => void;
}

function itemElementId(idx: number) {
  return `palette-item-${idx}`;
}

export function CommandPalette({ open, onClose }: Props) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const previousFocusRef = useRef<Element | null>(null);

  const { data: savedViewsData } = useSavedViews();
  const savedViews = savedViewsData?.views ?? [];

  const close = useCallback(() => {
    onClose();
  }, [onClose]);

  // Track previous focus; focus input when palette opens; restore focus on close
  useEffect(() => {
    if (open) {
      previousFocusRef.current = document.activeElement;
      // Defer to ensure the element is rendered before focusing
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      setQuery('');
      setActiveIndex(0);
      return () => clearTimeout(t);
    } else {
      if (previousFocusRef.current instanceof HTMLElement) {
        previousFocusRef.current.focus();
      }
    }
  }, [open]);

  const allItems = useMemo<PaletteItem[]>(() => {
    const pageItems: PaletteItem[] = PAGE_DESTINATIONS.map((p) => ({
      id: `page-${p.path.replace(/\//g, '-') || 'home'}`,
      label: p.label,
      sublabel: 'Page',
      category: 'page',
      onSelect: () => { navigate(p.path); close(); },
    }));

    const viewItems: PaletteItem[] = savedViews.map((v) => ({
      id: `view-${v.page}-${v.name}`,
      label: v.name,
      sublabel: `Saved view · ${v.page}`,
      category: 'view',
      onSelect: () => { navigate(`/${v.page}`); close(); },
    }));

    const actionItems: PaletteItem[] = [
      {
        id: 'action-create-incident',
        label: 'Create Incident',
        sublabel: 'Quick action',
        category: 'action',
        onSelect: () => { navigate('/incidents'); close(); },
      },
      {
        id: 'action-export-view',
        label: 'Export Current View',
        sublabel: 'Quick action',
        category: 'action',
        onSelect: () => { close(); },
      },
    ];

    return [...pageItems, ...viewItems, ...actionItems];
  }, [savedViews, navigate, close]);

  const filtered = useMemo<PaletteItem[]>(() => {
    if (!query) return allItems;
    return allItems.filter(
      (item) =>
        fuzzyMatch(query, item.label) ||
        (item.sublabel ? fuzzyMatch(query, item.sublabel) : false),
    );
  }, [allItems, query]);

  // Reset active index whenever filtered list changes length
  useEffect(() => {
    setActiveIndex(0);
  }, [filtered.length]);

  // Scroll active item into view
  useEffect(() => {
    if (!listRef.current) return;
    const activeEl = listRef.current.querySelector('[aria-selected="true"]');
    if (activeEl && typeof (activeEl as HTMLElement).scrollIntoView === 'function') {
      (activeEl as HTMLElement).scrollIntoView({ block: 'nearest' });
    }
  }, [activeIndex]);

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setActiveIndex((i) => (filtered.length === 0 ? 0 : Math.min(i + 1, filtered.length - 1)));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        filtered[activeIndex]?.onSelect();
        break;
      case 'Escape':
        e.preventDefault();
        close();
        break;
      case 'Tab':
        // Focus trap: keep focus within the palette
        e.preventDefault();
        break;
    }
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh]"
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60"
        onClick={close}
        aria-hidden="true"
        data-testid="palette-backdrop"
      />

      {/* Palette card */}
      <div className="relative w-full max-w-lg mx-4 bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-800">
          <svg
            className="w-4 h-4 text-gray-400 flex-shrink-0"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search pages, views, actions…"
            aria-label="Command palette search"
            aria-autocomplete="list"
            aria-controls="command-palette-listbox"
            aria-activedescendant={
              filtered.length > 0 ? itemElementId(activeIndex) : undefined
            }
            className="flex-1 bg-transparent text-white placeholder-gray-500 text-sm outline-none"
          />
          <kbd className="text-xs text-gray-600 border border-gray-700 rounded px-1.5 py-0.5">Esc</kbd>
        </div>

        {/* Results */}
        {filtered.length === 0 ? (
          <div className="px-4 py-6 text-center text-sm text-gray-500">No results</div>
        ) : (
          <ul
            id="command-palette-listbox"
            ref={listRef}
            role="listbox"
            aria-label="Command palette results"
            className="max-h-72 overflow-y-auto py-2"
          >
            {filtered.map((item, i) => (
              <li
                key={item.id}
                id={itemElementId(i)}
                role="option"
                aria-selected={i === activeIndex}
                onClick={item.onSelect}
                onMouseEnter={() => setActiveIndex(i)}
                className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors ${
                  i === activeIndex ? 'bg-gray-800' : 'hover:bg-gray-800/50'
                }`}
              >
                <CategoryBadge category={item.category} />
                <div className="min-w-0">
                  <div className="text-sm text-white truncate">{item.label}</div>
                  {item.sublabel && (
                    <div className="text-xs text-gray-500 truncate">{item.sublabel}</div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}

        {/* Footer hint */}
        <div className="px-4 py-2 border-t border-gray-800 flex items-center gap-4 text-xs text-gray-600">
          <span>
            <kbd className="border border-gray-700 rounded px-1">↑↓</kbd> navigate
          </span>
          <span>
            <kbd className="border border-gray-700 rounded px-1">↵</kbd> select
          </span>
          <span>
            <kbd className="border border-gray-700 rounded px-1">Esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  );
}

function CategoryBadge({ category }: { category: PaletteItem['category'] }) {
  if (category === 'page') {
    return (
      <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-blue-900/50 text-blue-300 flex-shrink-0">
        page
      </span>
    );
  }
  if (category === 'view') {
    return (
      <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-purple-900/50 text-purple-300 flex-shrink-0">
        view
      </span>
    );
  }
  return (
    <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-green-900/50 text-green-300 flex-shrink-0">
      action
    </span>
  );
}
