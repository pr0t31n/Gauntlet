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
    { id: 'tuxedo',       label: 'Tuxedo',       d: ['#0a0a0a','#e0e0e0'],   l: ['#ffffff','#111111'] },
    { id: 'meridian',     label: 'Meridian',     d: ['#0e1628','#4a88cc'],   l: ['#f6f9ff','#1a4a8c'] },
    { id: 'alabaster',    label: 'Alabaster',    d: ['#121416','#9caab8'],   l: ['#faf8f5','#2c3038'] },
    { id: 'noir',         label: 'Noir',         d: ['#08090e','#b0bcd0'],   l: ['#f4f5f8','#1c2440'] },
    { id: 'leadership',   label: 'Leadership',   d: ['#0b1428','#f5c842'],   l: ['#fdf8f0','#c8940a'] },
    { id: 'blueprint',    label: 'Blueprint',    d: ['#061830','#5090e0'],   l: ['#f0f5ff','#1a4898'] },
    { id: 'resume',       label: 'Resume',       d: ['#141008','#c8a860'],   l: ['#faf6ee','#1c2840'] },
    // Casual
    { id: 'foundry',      label: 'Foundry',      d: ['#0d0d0d','#f0a500'],   l: ['#f5f0e8','#c88000'] },
    { id: 'forge',        label: 'Forge',        d: ['#0a0804','#c8921f'],   l: ['#ede0c4','#8b5e10'] },
    { id: 'frigid',       label: 'Frigid',       d: ['#060e18','#5ab0d8'],   l: ['#e4f4ff','#1a70a0'] },
    { id: 'futuristic',   label: 'Futuristic',   d: ['#040f0c','#00c89c'],   l: ['#e0f4f0','#006858'] },
    { id: 'bloom',        label: 'Bloom',        d: ['#120e18','#c490c8'],   l: ['#f8f0f8','#9060a8'] },
    { id: 'prism',        label: 'Prism',        d: ['#0c0f2e','#c084fc'],   l: ['#ede9fe','#7c3aed'] },
    { id: 'ember',        label: 'Ember',        d: ['#140206','#e83020'],   l: ['#fff4ee','#b82010'] },
    { id: 'oldglory',     label: 'Old Glory',    d: ['#010410','#f03050'],   l: ['#e0e4f0','#021a5c'] },
    { id: 'alchemist',    label: 'Alchemist',    d: ['#020606','#50c8a0'],   l: ['#daf0ec','#0a2820'] },
    { id: 'speakeasy',    label: 'Speakeasy',    d: ['#0e0408','#c8841e'],   l: ['#f8f0e0','#8a1830'] },
    { id: 'jarhead',      label: 'Jarhead',      d: ['#0c0408','#c9a227'],   l: ['#ddc49c','#4a5020'] },
    // Nerdy
    { id: 'coruscant',    label: 'Coruscant',    d: ['#050007','#ff2040'],   l: ['#f5f8fe','#1a4a8c'] },
    { id: 'retro',        label: 'Retro',        d: ['#020a02','#33ff33'],   l: ['#0d0700','#ffaa00'] },
    { id: 'jarvis',       label: 'JARVIS',       d: ['#020c1b','#00d0ff'],   l: ['#d0e8f8','#0068c8'] },
    { id: 'hal9000',      label: 'HAL-9000',     d: ['#040202','#aa1800'],   l: ['#f8f5f2','#aa1800'] },
    { id: 'neuromancer',  label: 'Neuromancer',  d: ['#06030c','#d010b8'],   l: ['#faf0ff','#b010a0'] },
    { id: 'deepspace',    label: 'Deep Space',   d: ['#030610','#9070f0'],   l: ['#f0f4ff','#5040c0'] },
    { id: 'bladerunner',  label: 'Blade Runner', d: ['#0a0810','#ff8c00'],   l: ['#f4f0e8','#c06800'] },
    { id: 'synthwave',    label: 'Synthwave',    d: ['#0d0018','#ff0880'],   l: ['#fce8ff','#c00060'] },
    { id: 'hogwarts',     label: 'Hogwarts',     d: ['#05020a','#d4a017'],   l: ['#f5e6c8','#7c5020'] },
    { id: 'rivendell',    label: 'Rivendell',    d: ['#080602','#c8a840'],   l: ['#f4ead0','#6a4c18'] },
    { id: 'lcars',        label: 'LCARS',        d: ['#000000','#ff9900'],   l: ['#050a14','#9999cc'] },
    // Natural
    { id: 'espresso',     label: 'Espresso',     d: ['#130c06','#c07030'],   l: ['#fef8ee','#8b4a10'] },
    { id: 'terracotta',   label: 'Terracotta',   d: ['#180806','#d45828'],   l: ['#faf2e8','#b04020'] },
    { id: 'sage',         label: 'Sage',         d: ['#060c06','#78b860'],   l: ['#f4f9f0','#2a6830'] },
    { id: 'blush',        label: 'Blush',        d: ['#160608','#d06878'],   l: ['#fdf4f5','#8a2848'] },
  ];
  const PALETTES = PALETTES_META.map(p => p.id);

  // ── Category definitions ──────────────────────────────────────────────────
  const PALETTE_CATEGORIES = [
    { id: 'professional', label: 'Professional', palettes: ['tuxedo','meridian','alabaster','noir','leadership','blueprint','resume'] },
    { id: 'casual',       label: 'Casual',       palettes: ['foundry','forge','frigid','futuristic','bloom','prism','ember','oldglory','alchemist','speakeasy','jarhead'] },
    { id: 'nerdy',        label: 'Nerdy',        palettes: ['coruscant','retro','jarvis','hal9000','neuromancer','deepspace','bladerunner','synthwave','hogwarts','rivendell','lcars'] },
    { id: 'natural',      label: 'Natural',      palettes: ['espresso','terracotta','sage','blush'] },
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

    // Touch / mobile: toggle category sub-menus on tap
    ul.querySelectorAll('.palette-cat-header').forEach(header => {
      header.addEventListener('click', e => {
        e.stopPropagation();
        const item   = header.closest('.palette-cat-item');
        const isOpen = item.classList.contains('open');
        ul.querySelectorAll('.palette-cat-item.open').forEach(i => i.classList.remove('open'));
        if (!isOpen) item.classList.add('open');
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
    const rect = dd.getBoundingClientRect();
    if (rect.bottom > (window.innerHeight || document.documentElement.clientHeight)) {
      dd.classList.add('drop-up');
    }
  }

  function closePicker() {
    const picker = document.getElementById('palettePicker');
    const dd     = document.getElementById('palettePickerDropdown');
    if (picker) picker.setAttribute('aria-expanded', 'false');
    if (dd) {
      dd.style.display = 'none';
      dd.classList.remove('drop-up');
      dd.querySelectorAll('.palette-cat-item.open').forEach(i => i.classList.remove('open'));
    }
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
    const palette = PALETTES.includes(savedPalette) ? savedPalette : 'resume';
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
      const palette = html.getAttribute('data-palette') || 'resume';
      const newMode = mode === 'dark' ? 'light' : 'dark';
      apply(palette, newMode);
      refreshDropdownSwatches(newMode);
      return;
    }

    if (e.target.closest('#palettePickerDropdown')) return;

    if (e.target.closest('#palettePicker')) { togglePicker(); return; }

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
