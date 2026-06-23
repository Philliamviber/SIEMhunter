import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { EventDetailPanel } from '../EventDetailPanel';
import type { SecurityEvent } from '../../types/api';
import * as exportUtils from '../../utils/exportUtils';

// ── Minimal SecurityEvent factory ────────────────────────────────────────────

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    TimeGenerated: '2026-06-20T14:32:05.000Z',
    HostName: 'dc01.corp.local',
    EventID: 4624,
    EventRecordID: 'rec-001',
    ChannelName: 'Security',
    ProviderName: 'Microsoft-Windows-Security-Auditing',
    SubjectUserName: 'jdoe',
    SubjectUserSid: 'S-1-5-21-111',
    SubjectDomainName: 'CORP',
    TargetUserName: '',
    TargetUserSid: '',
    TargetDomainName: '',
    LogonType: 3,
    ServiceName: '',
    ProcessImagePath: '',
    CommandLine: '',
    ParentProcessImagePath: '',
    ParentCommandLine: '',
    GrantedAccess: '',
    ObjectName: '',
    FileMD5: '',
    FileSHA256: '',
    RegistryKey: '',
    SrcIpAddr: '10.0.0.5',
    SrcPort: 0,
    DstIpAddr: '',
    DstPort: 0,
    NetworkProtocol: '',
    ProvenanceTag: 'wef-collector:test',
    IngestTimestamp: '2026-06-20T14:32:10.000Z',
    UnmappedFields: '',
    ...overrides,
  };
}

function renderPanel(event: SecurityEvent, onClose = vi.fn()) {
  return render(
    <MemoryRouter>
      <EventDetailPanel event={event} onClose={onClose} />
    </MemoryRouter>
  );
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('EventDetailPanel', () => {
  describe('field rendering', () => {
    it('renders the HostName field in the header subtitle', () => {
      renderPanel(makeEvent());
      // HostName appears in at least the header subtitle — getAllByText returns all matches
      const matches = screen.getAllByText(/dc01\.corp\.local/);
      expect(matches.length).toBeGreaterThan(0);
    });

    it('renders EventID in the header subtitle', () => {
      renderPanel(makeEvent());
      expect(screen.getByText(/EID 4624/)).toBeTruthy();
    });

    it('renders ChannelName as labelled field row', () => {
      renderPanel(makeEvent());
      // The label is uppercased by CSS but the text content is the key name
      expect(screen.getByText('Security')).toBeTruthy();
    });

    it('renders SubjectUserName when non-empty', () => {
      renderPanel(makeEvent());
      expect(screen.getByText('jdoe')).toBeTruthy();
    });

    it('does not render rows for empty-string fields', () => {
      renderPanel(makeEvent({ TargetUserName: '' }));
      // TargetUserName is empty, so "TargetUserName" label should not appear
      // (the component only renders rows where val is truthy)
      const container = document.querySelector('[class*="fixed"]');
      expect(container?.textContent).not.toMatch(/^TargetUserName$/);
    });

    it('renders SrcIpAddr field', () => {
      renderPanel(makeEvent());
      expect(screen.getByText('10.0.0.5')).toBeTruthy();
    });

    it('formats TimeGenerated via formatTimestamp (contains UTC)', () => {
      renderPanel(makeEvent());
      // The formatted result for 2026-06-20T14:32:05.000Z contains "UTC"
      const utcValues = screen.getAllByText(/UTC/);
      expect(utcValues.length).toBeGreaterThan(0);
    });
  });

  describe('EventID description', () => {
    it('shows the description for EventID 4624', () => {
      renderPanel(makeEvent({ EventID: 4624 }));
      expect(
        screen.getByText('An account was successfully logged on')
      ).toBeTruthy();
    });

    it('shows the description for EventID 4688', () => {
      renderPanel(makeEvent({ EventID: 4688 }));
      expect(
        screen.getByText('A new process has been created')
      ).toBeTruthy();
    });

    it('does not show Event Description for an unknown EventID', () => {
      renderPanel(makeEvent({ EventID: 99999 }));
      expect(screen.queryByText('Event Description')).toBeNull();
    });
  });

  describe('UnmappedFields', () => {
    it('shows "empty" when UnmappedFields is blank', () => {
      renderPanel(makeEvent({ UnmappedFields: '' }));
      expect(screen.getByText('empty')).toBeTruthy();
    });

    it('shows "empty" when UnmappedFields is the literal "{}"', () => {
      renderPanel(makeEvent({ UnmappedFields: '{}' }));
      expect(screen.getByText('empty')).toBeTruthy();
    });

    it('renders non-empty UnmappedFields as preformatted text in a <pre> element', () => {
      const payload = JSON.stringify({ custom_field: 'value123' });
      const { container } = renderPanel(makeEvent({ UnmappedFields: payload }));
      const pre = container.querySelector('pre');
      expect(pre).not.toBeNull();
      expect(pre?.textContent).toContain('custom_field');
      expect(pre?.textContent).toContain('value123');
    });

    it('does not use dangerouslySetInnerHTML for UnmappedFields (XSS check)', () => {
      // If the component used dangerouslySetInnerHTML with this payload,
      // the <img> tag would be created in the DOM as an element.
      const xssPayload = JSON.stringify({ attack: '<img src=x onerror=alert(1)>' });
      const { container } = renderPanel(makeEvent({ UnmappedFields: xssPayload }));
      // The img must NOT exist as a real DOM element
      const imgs = container.querySelectorAll('img');
      expect(imgs.length).toBe(0);
      // The literal text should appear as inert text content inside <pre>
      const pre = container.querySelector('pre');
      expect(pre?.textContent).toContain('<img src=x onerror=alert(1)>');
    });

    it('renders malformed JSON in UnmappedFields as "empty"', () => {
      // JSON.parse throws — the catch block falls through and unmappedParsed stays null
      renderPanel(makeEvent({ UnmappedFields: '{not valid json' }));
      expect(screen.getByText('empty')).toBeTruthy();
    });
  });

  describe('CommandLine XSS safety (MUST-7)', () => {
    it('renders a CommandLine containing an HTML injection payload as plain text', () => {
      const malicious = '<img src=x onerror=alert(1)>';
      const { container } = renderPanel(makeEvent({ CommandLine: malicious }));
      // The literal string must appear in the DOM as text
      expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
      // No actual <img> element should exist
      expect(container.querySelectorAll('img').length).toBe(0);
    });
  });

  describe('pivot links', () => {
    it('renders "All events from this host" link', () => {
      renderPanel(makeEvent());
      expect(screen.getByText('All events from this host')).toBeTruthy();
    });

    it('host link points to /events with hostname param', () => {
      const { container } = renderPanel(makeEvent({ HostName: 'dc01.corp.local' }));
      const link = container.querySelector('a[href*="hostname=dc01"]');
      expect(link).not.toBeNull();
    });

    it('renders "All events by this user" link when SubjectUserName is set', () => {
      renderPanel(makeEvent({ SubjectUserName: 'jdoe' }));
      expect(screen.getByText('All events by this user')).toBeTruthy();
    });

    it('does not render "All events by this user" when SubjectUserName is empty', () => {
      renderPanel(makeEvent({ SubjectUserName: '' }));
      expect(screen.queryByText('All events by this user')).toBeNull();
    });

    it('renders "All events from this IP" link when SrcIpAddr is set', () => {
      renderPanel(makeEvent({ SrcIpAddr: '10.0.0.5' }));
      expect(screen.getByText('All events from this IP')).toBeTruthy();
    });

    it('does not render "All events from this IP" when SrcIpAddr is empty', () => {
      renderPanel(makeEvent({ SrcIpAddr: '' }));
      expect(screen.queryByText('All events from this IP')).toBeNull();
    });

    it('renders "All events with this EventID" link always', () => {
      renderPanel(makeEvent());
      expect(screen.getByText('All events with this EventID')).toBeTruthy();
    });
  });

  describe('export and copy actions (FR #25)', () => {
    beforeEach(() => {
      vi.spyOn(exportUtils, 'downloadFile').mockImplementation(() => {});
    });

    it('renders a Copy JSON button', () => {
      renderPanel(makeEvent());
      expect(screen.getByRole('button', { name: /copy.*json/i })).toBeTruthy();
    });

    it('renders an Export CSV button', () => {
      renderPanel(makeEvent());
      expect(screen.getByRole('button', { name: /export.*csv/i })).toBeTruthy();
    });

    it('Copy JSON button writes event data to clipboard', async () => {
      const writeText = vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText },
        configurable: true,
        writable: true,
      });

      renderPanel(makeEvent());
      await userEvent.click(screen.getByRole('button', { name: /copy.*json/i }));
      expect(writeText).toHaveBeenCalledOnce();

      const copied: string = writeText.mock.calls[0][0];
      const parsed = JSON.parse(copied);
      expect(parsed.HostName).toBe('dc01.corp.local');
      expect(parsed.EventID).toBe(4624);
    });

    it('Copy JSON button shows "Copied!" feedback after click', async () => {
      vi.fn().mockResolvedValue(undefined);
      Object.defineProperty(navigator, 'clipboard', {
        value: { writeText: vi.fn().mockResolvedValue(undefined) },
        configurable: true,
        writable: true,
      });

      renderPanel(makeEvent());
      const copyBtn = screen.getByRole('button', { name: /copy.*json/i });
      await userEvent.click(copyBtn);
      expect(copyBtn.textContent).toBe('Copied!');
    });

    it('Export CSV button calls downloadFile with CSV content', async () => {
      const downloadSpy = vi.spyOn(exportUtils, 'downloadFile');
      renderPanel(makeEvent());
      await userEvent.click(screen.getByRole('button', { name: /export.*csv/i }));
      expect(downloadSpy).toHaveBeenCalledOnce();
      const [content, filename, mime] = downloadSpy.mock.calls[0];
      expect(content).toContain('"TimeGenerated"');
      expect(filename).toMatch(/\.csv$/);
      expect(mime).toContain('text/csv');
    });

    it('Export CSV content is CSV-injection-safe for = prefix', async () => {
      const downloadSpy = vi.spyOn(exportUtils, 'downloadFile');
      renderPanel(makeEvent({ CommandLine: '=malicious()' }));
      await userEvent.click(screen.getByRole('button', { name: /export.*csv/i }));
      const content: string = downloadSpy.mock.calls[0][0];
      // The = prefix must be neutralized — should NOT appear as bare ="
      expect(content).not.toContain('"=malicious');
      // Should appear sanitized with a leading apostrophe
      expect(content).toContain("\"'=malicious");
    });
  });

  describe('close behaviour', () => {
    it('calls onClose when the close button is clicked', async () => {
      const onClose = vi.fn();
      renderPanel(makeEvent(), onClose);
      const closeBtn = screen.getByRole('button', { name: /close event detail/i });
      await userEvent.click(closeBtn);
      expect(onClose).toHaveBeenCalledOnce();
    });

    it('calls onClose when Escape key is pressed', async () => {
      const onClose = vi.fn();
      renderPanel(makeEvent(), onClose);
      await userEvent.keyboard('{Escape}');
      expect(onClose).toHaveBeenCalledOnce();
    });
  });
});
