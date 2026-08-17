// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Blackout Secure Security TXT Generator GitHub Action
// Copyright © 2025-2026 Blackout Secure
// Licensed under Apache License 2.0
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Expires directive parsing (RFC 9116 § 2.5.5).
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const DEFAULT_DAYS = 180;

/**
 * Parse an expires value from a relative or absolute form.
 *
 * Accepts ISO 8601 timestamps plus the relative shorthands `30d`, `6m`,
 * and `1y`. An empty value yields the 180-day default, which stays well
 * inside the one-year ceiling RFC 9116 recommends.
 *
 * @param {string} input - User input.
 * @param {Date} [now] - Clock injection point.
 * @returns {{date: string, daysFromNow: number}} Resolved expiry.
 */
function parseExpiresDate(input, now = new Date()) {
  let targetDate;
  let isoString;

  if (!input) {
    targetDate = new Date(now.getTime() + DEFAULT_DAYS * 24 * 60 * 60 * 1000);
    isoString = targetDate.toISOString();
  } else if (/^\d+d$/i.test(input)) {
    targetDate = new Date(now.getTime() + parseInt(input, 10) * 24 * 60 * 60 * 1000);
    isoString = targetDate.toISOString();
  } else if (/^\d+m$/i.test(input)) {
    targetDate = new Date(now);
    targetDate.setMonth(targetDate.getMonth() + parseInt(input, 10));
    isoString = targetDate.toISOString();
  } else if (/^\d+y$/i.test(input)) {
    targetDate = new Date(now);
    targetDate.setFullYear(targetDate.getFullYear() + parseInt(input, 10));
    isoString = targetDate.toISOString();
  } else {
    targetDate = new Date(input);
    if (isNaN(targetDate.getTime())) {
      throw new Error(
        `Invalid expires date format: "${input}". Use ISO 8601, "30d", "6m", or "1y".`,
      );
    }
    // Preserve the operator's original spelling when it is already absolute.
    isoString = input;
  }

  return {
    date: isoString,
    daysFromNow: Math.round((targetDate.getTime() - now.getTime()) / (24 * 60 * 60 * 1000)),
  };
}

module.exports = { DEFAULT_DAYS, parseExpiresDate };
