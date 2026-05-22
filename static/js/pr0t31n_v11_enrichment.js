/*
 * pr0t31n_v11_enrichment.js — Shared v1.1 enrichment renderer for pr0t31n
 * management Flask apps (Vantage, Crucible, Spectre, Gauntlet, Bastion).
 *
 * Reads a finding dict (post-universal-schema v1.1) and returns HTML for
 * a compact enrichment row: CVSS pill, CWE chips, MITRE ATT&CK chips,
 * compliance framework badges, KEV warning, confidence indicator,
 * API endpoint metadata, wireless data, etc.
 *
 * Each piece is rendered ONLY when the relevant field is populated, so
 * findings from a tool that hasn't adopted a given v1.1 field show
 * nothing extra (no empty placeholders).
 *
 * Distribution: VENDORED. Each app copies this file into its static dir.
 *
 * Usage in app JS:
 *   const html = window.renderV11Enrichment(finding);
 *   if (html) detailModal.appendChild(html);   // or set innerHTML
 *
 * No external dependencies. Pure DOM string builder.
 */
(function (root) {
  'use strict';

  function _esc(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function _list(v) {
    if (Array.isArray(v)) return v.filter(x => x !== null && x !== undefined && x !== '');
    if (v === null || v === undefined || v === '') return [];
    return [v];
  }

  function _badge(label, value, color) {
    return '<span class="v11-badge" style="display:inline-block;' +
           'padding:.1rem .4rem;margin:.1rem .15rem .1rem 0;border-radius:3px;' +
           'font-size:.7rem;font-family:var(--font-mono,monospace);' +
           'background:' + (color || 'var(--bg-input,#222)') + ';' +
           'color:var(--text-primary,#eee);' +
           'border:1px solid var(--border-dim,#444)">' +
           '<strong>' + _esc(label) + ':</strong> ' + _esc(value) + '</span>';
  }

  function _chip(text, color) {
    return '<span class="v11-chip" style="display:inline-block;' +
           'padding:.05rem .35rem;margin:.1rem .15rem .1rem 0;border-radius:3px;' +
           'font-size:.65rem;font-family:var(--font-mono,monospace);' +
           'background:' + (color || 'var(--bg-input,#222)') + ';' +
           'color:var(--text-primary,#eee);' +
           'border:1px solid var(--border-dim,#444)">' +
           _esc(text) + '</span>';
  }

  function _section(label, html) {
    if (!html) return '';
    return '<div class="v11-section" style="margin:.3rem 0;font-size:.72rem">' +
           '<span style="color:var(--text-muted,#888);font-weight:600;' +
           'margin-right:.4rem;text-transform:uppercase;font-size:.65rem">' +
           _esc(label) + '</span>' + html + '</div>';
  }

  function _cvssColor(score) {
    if (score === null || score === undefined) return null;
    const n = Number(score);
    if (isNaN(n)) return null;
    if (n >= 9.0) return '#a02020';     // critical
    if (n >= 7.0) return '#c04030';     // high
    if (n >= 4.0) return '#806020';     // medium
    if (n >  0.0) return '#406020';     // low
    return '#444';
  }

  /**
   * Build an HTML string for the v1.1 enrichment row of a finding.
   * Returns '' if the finding carries no v1.1 enrichment data.
   */
  function renderV11Enrichment(f) {
    if (!f || typeof f !== 'object') return '';
    var parts = [];

    // CVSS
    if (f.cvss_score !== null && f.cvss_score !== undefined && f.cvss_score !== '') {
      var cvssHtml = _badge('CVSS', String(f.cvss_score), _cvssColor(f.cvss_score));
      if (f.cvss_vector) {
        cvssHtml += ' <span style="color:var(--text-muted,#888);font-family:var(--font-mono,monospace);font-size:.65rem">' +
                    _esc(f.cvss_vector) + '</span>';
      }
      parts.push(_section('Severity', cvssHtml));
    }

    // CWE chips
    var cwe = _list(f.cwe);
    if (cwe.length) {
      parts.push(_section('CWE', cwe.map(function (c) {
        return '<a href="https://cwe.mitre.org/data/definitions/' + _esc(String(c).replace(/^CWE-/i, '')) +
               '.html" target="_blank" rel="noopener" style="text-decoration:none">' +
               _chip(c, '#2a3a2a') + '</a>';
      }).join('')));
    }

    // MITRE ATT&CK
    var mitre = _list(f.mitre_attack);
    if (mitre.length) {
      parts.push(_section('MITRE ATT&CK', mitre.map(function (m) {
        if (typeof m === 'string') return _chip(m, '#3a2a3a');
        var tech = m.technique || m.id || '';
        var name = m.name || m.tactic || '';
        var label = tech + (name ? ' — ' + name : '');
        return '<a href="https://attack.mitre.org/techniques/' + _esc(String(tech).replace(/\./g, '/')) +
               '/" target="_blank" rel="noopener" style="text-decoration:none">' +
               _chip(label, '#3a2a3a') + '</a>';
      }).join('')));
    }

    // KEV warning
    if (f.kev === true) {
      parts.push(_section('Known Exploited',
        '<span style="background:#a02020;color:#fff;padding:.1rem .5rem;border-radius:3px;' +
        'font-size:.7rem;font-weight:700">CISA KEV — actively exploited in the wild</span>'));
    }

    // Compliance frameworks (one chip per control per framework)
    var compliance = [];
    ['nist_800_53', 'nist_800_171', 'nist_csf2', 'pci_dss_4',
     'iso_27001', 'iso_27002', 'soc2', 'hitrust', 'gdpr'].forEach(function (fw) {
      var refs = _list(f[fw]);
      if (refs.length) {
        var label = fw.toUpperCase().replace('_', ' ');
        compliance.push('<span style="margin-right:.4rem">' +
          '<span style="color:var(--text-muted,#888);font-size:.65rem;margin-right:.2rem">' + label + ':</span>' +
          refs.map(function (r) { return _chip(r, '#2a2a3a'); }).join('') + '</span>');
      }
    });
    if (compliance.length) {
      parts.push(_section('Compliance', compliance.join('')));
    }

    // OWASP API (separate from owasp)
    if (f.owasp_api) parts.push(_section('OWASP API', _chip(f.owasp_api, '#3a2a2a')));

    // Granular remediation
    var rem = [];
    if (f.remediation_effort)    rem.push(_badge('Effort',    f.remediation_effort));
    if (f.remediation_component) rem.push(_badge('Component', f.remediation_component));
    if (f.remediation_category)  rem.push(_badge('Category',  f.remediation_category));
    if (rem.length) parts.push(_section('Remediation', rem.join('')));

    // External scanner IDs
    var ext = [];
    if (f.nessus_plugin_id) ext.push(_badge('Nessus', f.nessus_plugin_id));
    if (f.qualys_qid)       ext.push(_badge('Qualys', f.qualys_qid));
    if (ext.length) parts.push(_section('Scanner IDs', ext.join('')));

    // API endpoint metadata (Siphon)
    var api = [];
    if (f.api_method)         api.push(_badge('Method', f.api_method));
    if (f.api_endpoint_path)  api.push(_chip(f.api_endpoint_path, '#2a3a3a'));
    if (f.api_from_spec === true)  api.push(_chip('In Spec',    '#2a3a2a'));
    if (f.is_rogue_endpoint === true) api.push(_chip('ROGUE',   '#3a2a2a'));
    if (api.length) parts.push(_section('API', api.join('')));

    // Wireless (Aether) — ssid/bssid/wireless_data
    var wifi = [];
    if (f.ssid)  wifi.push(_badge('SSID',  f.ssid));
    if (f.bssid) wifi.push(_badge('BSSID', f.bssid));
    if (f.wireless_data && typeof f.wireless_data === 'object') {
      var wd = f.wireless_data;
      if (wd.channel)    wifi.push(_badge('Ch',     wd.channel));
      if (wd.encryption) wifi.push(_badge('Enc',    wd.encryption));
    }
    if (wifi.length) parts.push(_section('Wireless', wifi.join('')));

    // Gearbox-style network/device context
    var net = [];
    if (f.subdevice) net.push(_badge('Subdevice', f.subdevice));
    if (f.interface) net.push(_badge('Interface', f.interface));
    if (f.instance)  net.push(_badge('Instance',  f.instance));
    if (net.length) parts.push(_section('Device', net.join('')));

    // Classification + confidence
    var meta = [];
    if (f.classification) meta.push(_badge('Class',      f.classification));
    if (f.confidence)     meta.push(_badge('Confidence', f.confidence));
    if (f.accepted === true) meta.push(_chip('ACCEPTED', '#2a3a2a'));
    if (meta.length) parts.push(_section('Status', meta.join('')));

    // Catalogue lineage
    var lin = [];
    if (_list(f.aliases).length) {
      lin.push('<span style="color:var(--text-muted,#888);font-size:.65rem;margin-right:.3rem">Aliases:</span>' +
               _list(f.aliases).slice(0, 5).map(function (a) { return _chip(a); }).join(''));
    }
    if (_list(f.source_tools).length) {
      lin.push('<span style="color:var(--text-muted,#888);font-size:.65rem;margin-right:.3rem">Detectable by:</span>' +
               _list(f.source_tools).slice(0, 8).map(function (t) { return _chip(t, '#2a2a3a'); }).join(''));
    }
    if (lin.length) parts.push(_section('Catalogue', lin.join(' ')));

    // Searchsploit / Metasploit hints
    var ex = [];
    if (_list(f.searchsploit_terms).length) {
      ex.push('<span style="color:var(--text-muted,#888);font-size:.65rem;margin-right:.3rem">SearchSploit:</span>' +
              _list(f.searchsploit_terms).map(function (t) { return _chip(t, '#3a2a2a'); }).join(''));
    }
    if (_list(f.metasploit_modules).length) {
      ex.push('<span style="color:var(--text-muted,#888);font-size:.65rem;margin-right:.3rem">Metasploit:</span>' +
              _list(f.metasploit_modules).map(function (m) { return _chip(m, '#3a2a2a'); }).join(''));
    }
    if (ex.length) parts.push(_section('Exploit Refs', ex.join(' ')));

    if (!parts.length) return '';
    return '<div class="v11-enrichment" style="padding:.4rem .6rem;' +
           'background:var(--bg-tertiary,rgba(255,255,255,.02));' +
           'border-left:2px solid var(--accent-primary,#4a8);' +
           'margin:.3rem 0;border-radius:0 4px 4px 0">' +
           parts.join('') + '</div>';
  }

  root.renderV11Enrichment = renderV11Enrichment;
}(typeof window !== 'undefined' ? window : globalThis));
