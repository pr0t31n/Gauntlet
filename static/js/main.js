/**
 * Gauntlet — main.js
 * Theme system: palette + mode (dark/light), stored in localStorage.
 * Custom swatch picker with category flyout replaces the native <select>.
 */

(function () {
  'use strict';

  const html = document.documentElement;

  const KEY_PALETTE = 'gauntlet-palette';
  const KEY_MODE    = 'gauntlet-mode';

  // ── Palette metadata: name, dark swatch [bg, accent], light swatch [bg, accent] ──
  const PALETTES_META = [
    // Professional
    { id: 'tuxedo',       label: 'Tuxedo',              d: ['#0a0a0a','#ffffff'], l: ['#ffffff','#000000'] },
    { id: 'meridian',     label: 'Meridian',            d: ['#0e1628','#4a88cc'], l: ['#f6f9ff','#1a4a8c'] },
    { id: 'alabaster',    label: 'Alabaster',           d: ['#121416','#9caab8'], l: ['#faf8f5','#2c3038'] },
    { id: 'noir',         label: 'Noir',                d: ['#08090e','#b0bcd0'], l: ['#f4f5f8','#1c2440'] },
    // Casual
    { id: 'forge',        label: 'Forge',               d: ['#0a0804','#c8921f'], l: ['#ede0c4','#8b5e10'] },
    { id: 'frigid',       label: 'Frigid',              d: ['#060e18','#5ab0d8'], l: ['#e4f4ff','#1a70a0'] },
    { id: 'futuristic',   label: 'Futuristic',          d: ['#040f0c','#00c89c'], l: ['#e0f4f0','#006858'] },
    { id: 'bloom',        label: 'Bloom',               d: ['#120e18','#c490c8'], l: ['#f8f0f8','#9060a8'] },
    { id: 'prism',        label: 'Prism',               d: ['#0c0f2e','#c084fc'], l: ['#ede9fe','#7c3aed'] },
    { id: 'speakeasy',    label: 'Speakeasy',           d: ['#0e0408','#c8841e'], l: ['#f8f0e0','#8a1830'] },
    { id: 'jarhead',      label: 'Jarhead',             d: ['#0c0408','#c9a227'], l: ['#ddc49c','#4a5020'] },
    // Nerdy
    { id: 'coruscant',    label: 'Coruscant',           d: ['#050007','#e01030'], l: ['#f5f8fe','#1a4a8c'] },
    { id: 'retro',        label: 'Retro',               d: ['#020a02','#33ff33'], l: ['#0d0700','#ffaa00'] },
    { id: 'jarvis',       label: 'JARVIS',              d: ['#020c1b','#00d0ff'], l: ['#d0e8f8','#0068c8'] },
    { id: 'hogwarts',     label: 'Hogwarts',            d: ['#05020a','#d4a017'], l: ['#f5e6c8','#7c5020'] },
    { id: 'rivendell',    label: 'Rivendell',           d: ['#080602','#c8a840'], l: ['#f4ead0','#6a4c18'] },
    { id: 'lcars',        label: 'LCARS',               d: ['#000000','#FF9900'], l: ['#050a14','#9999CC'] },
  ];
  const PALETTES = PALETTES_META.map(p => p.id);

  // ── Category definitions ──────────────────────────────────────────────────
  const PALETTE_CATEGORIES = [
    { id: 'professional', label: 'Professional', palettes: ['tuxedo','meridian','alabaster','noir'] },
    { id: 'casual',       label: 'Casual',       palettes: ['forge','frigid','futuristic','bloom','prism','speakeasy','jarhead','oldglory','alchemist'] },
    { id: 'nerdy',        label: 'Nerdy',        palettes: ['coruscant','retro','jarvis','hogwarts','rivendell','doom','lcars'] },
  ];

  // ── Storage helpers ───────────────────────────────────────────────────────
  function load(key)      { try { return localStorage.getItem(key); } catch { return null; } }
  function save(key, val) { try { localStorage.setItem(key, val);   } catch {} }

  // ── Apply palette + mode atomically ──────────────────────────────────────
  function apply(palette, mode) {
    html.setAttribute('data-palette', palette);
    html.setAttribute('data-mode',    mode);

    const modeLabel = document.getElementById('modeLabel');
    if (modeLabel) {
      if (palette === 'coruscant') {
        modeLabel.textContent = mode === 'light' ? 'Jedi' : 'Sith';
      } else {
        modeLabel.textContent = mode === 'dark' ? 'Dark' : 'Light';
      }
    }

    // Sync hidden select
    const sel = document.getElementById('paletteSelect');
    if (sel) sel.value = palette;

    // Update swatch picker UI
    updatePickerUI(palette, mode);

    save(KEY_PALETTE, palette);
    save(KEY_MODE,    mode);
  }

  // ── Swatch picker ─────────────────────────────────────────────────────────
  function swatchHtml(colors) {
    return colors.map(c =>
      `<span style="display:inline-block;width:10px;height:10px;border-radius:50%;
                    background:${c};border:1px solid rgba(128,128,128,.3);
                    flex-shrink:0"></span>`
    ).join('');
  }

  function updatePickerUI(palette, mode) {
    const label    = document.getElementById('palettePickerLabel');
    const swatches = document.getElementById('palettePickerSwatches');
    if (!label || !swatches) return;
    const meta = PALETTES_META.find(p => p.id === palette) || PALETTES_META[0];
    const cols = mode === 'dark' ? meta.d : meta.l;
    label.textContent  = meta.label;
    swatches.innerHTML = swatchHtml(cols);
  }

  function buildDropdown() {
    const ul = document.getElementById('palettePickerDropdown');
    if (!ul || ul.children.length) return;  // already built
    const mode = html.getAttribute('data-mode') || 'dark';

    ul.innerHTML = PALETTE_CATEGORIES.map(cat => {
      const itemsHtml = cat.palettes.map(pid => {
        const meta = PALETTES_META.find(p => p.id === pid);
        if (!meta) return '';
        const cols = mode === 'dark' ? meta.d : meta.l;
        return `<li role="option" data-palette="${meta.id}"
                    style="display:flex;align-items:center;gap:.45rem;padding:.32rem .6rem;
                           cursor:pointer;white-space:nowrap;font-size:.75rem">
                  ${swatchHtml(cols)}
                  <span>${meta.label}</span>
                </li>`;
      }).join('');

      return `<li class="palette-cat-item" data-cat="${cat.id}">
        <div class="palette-cat-header" role="presentation">
          <span>${cat.label}</span>
          <span class="cat-arrow">▸</span>
        </div>
        <ul class="palette-cat-sub" role="group" aria-label="${cat.label} themes">
          ${itemsHtml}
        </ul>
      </li>`;
    }).join('');

    // Attach click handlers to all theme items
    ul.querySelectorAll('li[data-palette]').forEach(li => {
      li.addEventListener('click', e => {
        e.stopPropagation();
        apply(li.dataset.palette, html.getAttribute('data-mode') || 'dark');
        closePicker();
      });
    });
  }

  function refreshDropdownSwatches(mode) {
    const ul = document.getElementById('palettePickerDropdown');
    if (!ul) return;
    ul.querySelectorAll('li[data-palette]').forEach(li => {
      const meta = PALETTES_META.find(p => p.id === li.dataset.palette);
      if (!meta) return;
      const cols = mode === 'dark' ? meta.d : meta.l;
      const spans = li.querySelectorAll('span[style*="border-radius:50%"]');
      spans.forEach((s, i) => { if (cols[i]) s.style.background = cols[i]; });
    });
  }

  function openPicker() {
    const picker = document.getElementById('palettePicker');
    const dd     = document.getElementById('palettePickerDropdown');
    if (!picker || !dd) return;
    buildDropdown();
    refreshDropdownSwatches(html.getAttribute('data-mode') || 'dark');
    dd.classList.remove('drop-up');
    picker.setAttribute('aria-expanded', 'true');
    dd.style.display = 'block';
    // Flip upward if the dropdown extends past the viewport bottom
    const rect = dd.getBoundingClientRect();
    if (rect.bottom > (window.innerHeight || document.documentElement.clientHeight)) {
      dd.classList.add('drop-up');
    }
  }

  function closePicker() {
    const picker = document.getElementById('palettePicker');
    const dd     = document.getElementById('palettePickerDropdown');
    if (picker) picker.setAttribute('aria-expanded', 'false');
    if (dd) { dd.style.display = 'none'; dd.classList.remove('drop-up'); }
  }

  function togglePicker() {
    const dd = document.getElementById('palettePickerDropdown');
    if (!dd) return;
    dd.style.display === 'block' ? closePicker() : openPicker();
  }

  // ── Init ─────────────────────────────────────────────────────────────────
  (function init() {
    const savedPalette = load(KEY_PALETTE);
    const savedMode    = load(KEY_MODE);
    const palette = PALETTES.includes(savedPalette) ? savedPalette : 'tuxedo';
    const mode    = (savedMode === 'light' || savedMode === 'dark')
                    ? savedMode
                    : 'light';
    apply(palette, mode);
  })();

  // ── Dark / light toggle ───────────────────────────────────────────────────
  document.addEventListener('click', function(e) {
    const toggleBtn = e.target.closest('#themeToggle');
    if (toggleBtn) {
      const mode    = html.getAttribute('data-mode')    || 'light';
      const palette = html.getAttribute('data-palette') || 'tuxedo';
      const newMode = mode === 'dark' ? 'light' : 'dark';
      apply(palette, newMode);
      refreshDropdownSwatches(newMode);
      return;
    }

    // Palette picker open/close
    const picker = e.target.closest('#palettePicker');
    if (picker) { togglePicker(); return; }

    // Click outside closes picker
    closePicker();
  });

  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closePicker();
    const picker = document.getElementById('palettePicker');
    if (document.activeElement === picker && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault(); togglePicker();
    }
    if (e.key === 'Tab') document.body.classList.add('keyboard-nav');
  });
  document.addEventListener('mousedown', () => document.body.classList.remove('keyboard-nav'));

  // ── Date Input Mask (MM/DD/YYYY) ──────────────────────────────────────────
  document.addEventListener('input', function(e) {
    const inp = e.target;
    if (!inp.classList.contains('date-input') &&
        !(inp.getAttribute && inp.getAttribute('pattern') &&
          inp.getAttribute('pattern').includes('d{2}'))) return;
    let v = inp.value.replace(/\D/g, '').slice(0, 8);
    if (v.length >= 5) v = v.slice(0,2) + '/' + v.slice(2,4) + '/' + v.slice(4);
    else if (v.length >= 3) v = v.slice(0,2) + '/' + v.slice(2);
    inp.value = v;
  }, true);

})();
