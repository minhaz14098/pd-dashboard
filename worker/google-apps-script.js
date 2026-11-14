/**
 * Optional append-only Google Sheets writer. Deploy as a web app that runs as
 * the spreadsheet owner. Store SHEETS_WRITE_KEY and tracker/costing spreadsheet
 * IDs plus sheet tab IDs (the numeric gid from each Google Sheets URL) in Script Properties.
 */
function doPost(e) {
  const props = PropertiesService.getScriptProperties();
  const body = JSON.parse((e && e.postData && e.postData.contents) || '{}');
  // Apps Script Web Apps do not expose arbitrary Authorization headers to doPost.
  // Send the key in the JSON body from a trusted Worker instead.
  if (body.key !== props.getProperty('SHEETS_WRITE_KEY')) return output({ error: 'Unauthorized' });
  if (body.mode !== 'append' || !Array.isArray(body.rows) || !body.rows.length || body.rows.length > 5000) {
    return output({ error: 'Expected append mode with 1–5000 rows' });
  }
  const config = body.sheet === 'tracker'
    ? ['TRACKER_SPREADSHEET_ID', 'TRACKER_SHEET_GID']
    : body.sheet === 'costing'
      ? ['COSTING_SPREADSHEET_ID', 'COSTING_SHEET_GID']
      : null;
  if (!config) return output({ error: 'Unknown sheet target' });
  const spreadsheetId = props.getProperty(config[0]);
  const rawSheetGid = props.getProperty(config[1]);
  const sheetGid = Number(rawSheetGid);
  if (!spreadsheetId || !rawSheetGid || !Number.isInteger(sheetGid)) return output({ error: 'Target spreadsheet configuration is missing' });
  const spreadsheet = SpreadsheetApp.openById(spreadsheetId);
  const sheet = spreadsheet.getSheetById(sheetGid);
  if (!sheet) return output({ error: 'Configured sheet tab was not found' });
  const values = body.rows.map(row => Array.isArray(row) ? row : [row]);
  const width = Math.max(...values.map(row => row.length));
  const normalized = values.map(row => row.concat(Array(Math.max(0, width - row.length)).fill('')));
  const start = sheet.getLastRow() + 1;
  sheet.getRange(start, 1, normalized.length, width).setValues(normalized);
  return output({ ok: true, appended: normalized.length, startRow: start });
}

function output(value) {
  return ContentService.createTextOutput(JSON.stringify(value)).setMimeType(ContentService.MimeType.JSON);
}
