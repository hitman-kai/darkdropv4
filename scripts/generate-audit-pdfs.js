#!/usr/bin/env node
/**
 * Generate professional PDF audit reports from markdown source files.
 * Usage: node scripts/generate-audit-pdfs.js
 */

const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const AUDITS = [
  {
    src: path.join(__dirname, '..', 'audits', 'AUDIT-01-MANUAL-REVIEW.md'),
    dst: path.join(__dirname, '..', 'audits', 'AUDIT-01-MANUAL-REVIEW.pdf'),
    title: 'DarkDrop V4 — Security Audit #1: Manual Review',
    date: 'April 6, 2026',
    subtitle: 'Fee system, credit notes, treasury, relay trust model',
  },
  {
    src: path.join(__dirname, '..', 'audits', 'AUDIT-02-CODE-REVIEW.md'),
    dst: path.join(__dirname, '..', 'audits', 'AUDIT-02-CODE-REVIEW.pdf'),
    title: 'DarkDrop V4 — Security Audit #2: Code Review',
    date: 'April 7, 2026',
    subtitle: 'Full instruction-level review, all modules',
  },
  {
    src: path.join(__dirname, '..', 'audits', 'AUDIT-03-POST-FIX-REVIEW.md'),
    dst: path.join(__dirname, '..', 'audits', 'AUDIT-03-POST-FIX-REVIEW.pdf'),
    title: 'DarkDrop V4 — Security Audit #3: Post-Fix Review',
    date: 'April 8, 2026',
    subtitle: 'Fix verification (H-01, M-01, L-03) + admin_sweep + full re-audit',
  },
];

const PROGRAM_ID = 'GSig1QYVwPVhHF6oVEwhadAwdWjTqtq6H5cSMEkfAgkU';

function parseMarkdown(text) {
  const lines = text.split('\n');
  const blocks = [];
  let inCodeBlock = false;
  let codeBuffer = [];
  let inTable = false;
  let tableRows = [];

  for (const line of lines) {
    if (line.startsWith('```')) {
      if (inCodeBlock) {
        blocks.push({ type: 'code', content: codeBuffer.join('\n') });
        codeBuffer = [];
        inCodeBlock = false;
      } else {
        if (inTable) {
          blocks.push({ type: 'table', rows: tableRows });
          tableRows = [];
          inTable = false;
        }
        inCodeBlock = true;
      }
      continue;
    }

    if (inCodeBlock) {
      codeBuffer.push(line);
      continue;
    }

    // Table detection
    if (line.includes('|') && line.trim().startsWith('|')) {
      const cells = line.split('|').slice(1, -1).map(c => c.trim());
      // Skip separator rows
      if (cells.every(c => /^[-:]+$/.test(c))) continue;
      if (!inTable) inTable = true;
      tableRows.push(cells);
      continue;
    } else if (inTable) {
      blocks.push({ type: 'table', rows: tableRows });
      tableRows = [];
      inTable = false;
    }

    if (line.startsWith('# ')) {
      blocks.push({ type: 'h1', content: line.slice(2).trim() });
    } else if (line.startsWith('## ')) {
      blocks.push({ type: 'h2', content: line.slice(3).trim() });
    } else if (line.startsWith('### ')) {
      blocks.push({ type: 'h3', content: line.slice(4).trim() });
    } else if (line.startsWith('---')) {
      blocks.push({ type: 'hr' });
    } else if (line.trim() === '') {
      blocks.push({ type: 'blank' });
    } else {
      // Merge consecutive text lines
      const last = blocks[blocks.length - 1];
      const cleanLine = line.replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1');
      if (last && last.type === 'text') {
        last.content += ' ' + cleanLine;
      } else {
        blocks.push({ type: 'text', content: cleanLine });
      }
    }
  }

  if (inTable && tableRows.length) {
    blocks.push({ type: 'table', rows: tableRows });
  }

  return blocks;
}

function generatePDF(audit) {
  const md = fs.readFileSync(audit.src, 'utf8');
  const blocks = parseMarkdown(md);

  const doc = new PDFDocument({
    size: 'A4',
    bufferPages: true,
    margins: { top: 60, bottom: 60, left: 50, right: 50 },
    info: {
      Title: audit.title,
      Author: 'DarkDrop Security Review',
      Subject: `Security Audit - ${audit.date}`,
    },
  });

  const stream = fs.createWriteStream(audit.dst);
  doc.pipe(stream);

  const pageWidth = doc.page.width - doc.page.margins.left - doc.page.margins.right;

  // Title page
  doc.moveDown(6);
  doc.fontSize(24).font('Helvetica-Bold').text(audit.title, { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(14).font('Helvetica').text(audit.date, { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(11).font('Helvetica').text(audit.subtitle, { align: 'center', color: '#555' });
  doc.moveDown(2);
  doc.fontSize(10).font('Courier').text(`Program ID: ${PROGRAM_ID}`, { align: 'center' });
  doc.moveDown(1);
  doc.fontSize(10).font('Helvetica').text('Cluster: Devnet', { align: 'center' });
  doc.moveDown(4);
  doc.fontSize(9).font('Helvetica').fillColor('#888')
    .text('CONFIDENTIAL — Security Audit Report', { align: 'center' });
  doc.fillColor('#000');

  doc.addPage();

  // Content
  for (const block of blocks) {
    // Check if we need a new page
    if (doc.y > doc.page.height - 100) {
      doc.addPage();
    }

    switch (block.type) {
      case 'h1':
        doc.moveDown(0.5);
        doc.fontSize(18).font('Helvetica-Bold').text(block.content);
        doc.moveDown(0.3);
        // Underline
        doc.moveTo(doc.page.margins.left, doc.y)
          .lineTo(doc.page.margins.left + pageWidth, doc.y)
          .lineWidth(1).stroke('#333');
        doc.moveDown(0.5);
        break;

      case 'h2':
        doc.moveDown(0.5);
        doc.fontSize(14).font('Helvetica-Bold').text(block.content);
        doc.moveDown(0.2);
        doc.moveTo(doc.page.margins.left, doc.y)
          .lineTo(doc.page.margins.left + pageWidth, doc.y)
          .lineWidth(0.5).stroke('#999');
        doc.moveDown(0.3);
        break;

      case 'h3':
        doc.moveDown(0.3);
        doc.fontSize(12).font('Helvetica-Bold').text(block.content);
        doc.moveDown(0.2);
        break;

      case 'text':
        doc.fontSize(10).font('Helvetica').text(block.content, {
          align: 'left',
          lineGap: 2,
        });
        doc.moveDown(0.2);
        break;

      case 'code':
        doc.moveDown(0.2);
        const codeX = doc.page.margins.left + 5;
        const codeY = doc.y;
        const codeLines = block.content.split('\n');
        const codeHeight = codeLines.length * 12 + 10;

        if (doc.y + codeHeight > doc.page.height - 80) {
          doc.addPage();
        }

        doc.rect(doc.page.margins.left, doc.y, pageWidth, Math.min(codeHeight, 300))
          .fill('#f5f5f5');
        doc.fillColor('#000');
        doc.fontSize(8).font('Courier');
        for (const codeLine of codeLines.slice(0, 25)) {
          doc.text(codeLine, codeX, doc.y + 2, { width: pageWidth - 10 });
        }
        if (codeLines.length > 25) {
          doc.text(`... (${codeLines.length - 25} more lines)`, codeX);
        }
        doc.moveDown(0.3);
        break;

      case 'table':
        if (block.rows.length === 0) break;
        doc.moveDown(0.2);

        const numCols = block.rows[0].length;
        const colWidth = pageWidth / numCols;
        const rowHeight = 18;

        if (doc.y + (block.rows.length * rowHeight) > doc.page.height - 80) {
          doc.addPage();
        }

        for (let r = 0; r < block.rows.length; r++) {
          const row = block.rows[r];
          const y = doc.y;

          // Header row background
          if (r === 0) {
            doc.rect(doc.page.margins.left, y, pageWidth, rowHeight).fill('#e8e8e8');
            doc.fillColor('#000');
          }

          // Alternating row background
          if (r > 0 && r % 2 === 0) {
            doc.rect(doc.page.margins.left, y, pageWidth, rowHeight).fill('#f8f8f8');
            doc.fillColor('#000');
          }

          // Cell text
          for (let c = 0; c < numCols; c++) {
            const cellText = (row[c] || '').replace(/\*\*(.*?)\*\*/g, '$1').replace(/`(.*?)`/g, '$1');
            const x = doc.page.margins.left + (c * colWidth) + 4;
            doc.fontSize(r === 0 ? 8 : 8)
              .font(r === 0 ? 'Helvetica-Bold' : 'Helvetica')
              .text(cellText, x, y + 4, {
                width: colWidth - 8,
                height: rowHeight,
                ellipsis: true,
              });
          }

          // Row border
          doc.moveTo(doc.page.margins.left, y + rowHeight)
            .lineTo(doc.page.margins.left + pageWidth, y + rowHeight)
            .lineWidth(0.3).stroke('#ccc');

          doc.y = y + rowHeight;
        }
        doc.moveDown(0.3);
        break;

      case 'hr':
        doc.moveDown(0.3);
        doc.moveTo(doc.page.margins.left, doc.y)
          .lineTo(doc.page.margins.left + pageWidth, doc.y)
          .lineWidth(0.5).stroke('#ccc');
        doc.moveDown(0.3);
        break;

      case 'blank':
        doc.moveDown(0.2);
        break;
    }
  }

  // Footer on each page
  const pages = doc.bufferedPageRange();
  for (let i = 0; i < pages.count; i++) {
    doc.switchToPage(i);
    doc.fontSize(8).font('Helvetica').fillColor('#999');
    doc.text(
      `${audit.title} | ${audit.date} | Page ${i + 1} of ${pages.count}`,
      doc.page.margins.left,
      doc.page.height - 40,
      { align: 'center', width: pageWidth }
    );
    doc.fillColor('#000');
  }

  doc.end();
  return new Promise((resolve) => stream.on('finish', resolve));
}

async function main() {
  for (const audit of AUDITS) {
    console.log(`Generating: ${path.basename(audit.dst)}`);
    await generatePDF(audit);
    const stat = fs.statSync(audit.dst);
    console.log(`  -> ${(stat.size / 1024).toFixed(0)} KB`);
  }
  console.log('Done.');
}

main().catch(console.error);
