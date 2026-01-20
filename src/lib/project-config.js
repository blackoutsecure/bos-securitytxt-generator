/**
 * Copyright 2025 Blackout Secure
 * SPDX-License-Identifier: Apache-2.0
 *
 * Project configuration utilities
 */

function getSecurityTxtHeader() {
  return `# Security.txt file
# Per RFC 9116: https://www.rfc-editor.org/rfc/rfc9116
#
# This file provides information for security researchers
# to responsibly report security vulnerabilities.`;
}

module.exports = {
  getSecurityTxtHeader,
};
