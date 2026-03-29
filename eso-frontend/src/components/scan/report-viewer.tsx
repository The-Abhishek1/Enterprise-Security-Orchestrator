// src/components/scan/report-viewer.tsx
'use client';
import { scans } from '@/lib/api';

export default function ReportViewer({ report, processId }: { report: string; processId: string }) {
  const html = mdToHtml(report);

  return (
    <div className="glass p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-bold uppercase tracking-wide text-gray-400 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-500" /> Pentest Report
        </h3>
        <a href={scans.pdfUrl(processId)} target="_blank" rel="noopener" className="btn-ghost text-xs">
          📥 Download PDF
        </a>
      </div>
      <div className="report-content text-sm leading-relaxed" dangerouslySetInnerHTML={{ __html: html }} />
      <style jsx>{`
        .report-content h1 { font-size: 18px; color: #818cf8; font-weight: 700; margin: 20px 0 8px; }
        .report-content h2 { font-size: 15px; color: #a78bfa; font-weight: 600; margin: 18px 0 6px; padding-bottom: 4px; border-bottom: 1px solid rgba(255,255,255,0.06); }
        .report-content table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 12px; font-family: var(--font-mono, monospace); }
        .report-content th { background: rgba(99,102,241,0.1); padding: 8px 10px; text-align: left; color: #818cf8; }
        .report-content td { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); }
        .report-content strong { color: #a78bfa; }
        .report-content p { margin: 6px 0; }
      `}</style>
    </div>
  );
}

function mdToHtml(md: string): string {
  return md
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/^\d+\.\s(.+)$/gm, '<p style="padding-left:16px">• $1</p>')
    .replace(/^- (.+)$/gm, '<p style="padding-left:16px">• $1</p>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\|(.+)\|/g, (match) => {
      const cells = match.split('|').filter(c => c.trim());
      if (cells.every(c => /^[-\s]+$/.test(c))) return '';
      return '<tr>' + cells.map(c => `<td>${c.trim()}</td>`).join('') + '</tr>';
    })
    .replace(/(<tr>.*?<\/tr>\s*)+/gs, '<table>$&</table>')
    .replace(/\n\n/g, '<br>');
}
