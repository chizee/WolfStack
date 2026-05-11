/* Written by Paul Clevett */
/* (C)Copyright Wolf Software Systems Ltd */
/* https://wolf.uk.com */

// ─── Clean Icon Theme ─────────────────────────────────────────────────────
// Replaces emoji glyphs with inline line-icon SVGs (Lucide-style) at render
// time. Mirrors the existing icon-pack DOM walker (replaceEmojisWithPackIcons)
// but emits inline SVG instead of <img> tags — no network fetches, no extra
// server endpoints, currentColor so themes still drive the colour.
//
// Wired into app.js via initIconTheme(): when currentIconTheme === 'clean',
// translateEmojisToCleanSvg() runs once on the body and observeForCleanIcons()
// keeps later mutations in sync.

// Inner SVG bodies (24×24 viewBox, 2px stroke, no fill, currentColor).
// Add more entries as the EMOJI_TO_SEMANTIC table grows — missing entries
// fall through to the original emoji glyph.
const CLEAN_ICONS = {
    home:        '<path d="M3 12 12 3l9 9"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    package:     '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="M3.3 7 12 12l8.7-5"/><path d="M12 22V12"/>',
    settings:    '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
    computer:    '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    save:        '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    globe:       '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
    lock:        '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    key:         '<circle cx="7.5" cy="15.5" r="3.5"/><path d="m10 13 11-11"/><path d="m16 7 3 3"/>',
    chart:       '<line x1="6" y1="20" x2="6" y2="14"/><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/>',
    'chart-up':  '<polyline points="22 7 13.5 15.5 8.5 10.5 2 17"/><polyline points="16 7 22 7 22 13"/>',
    wrench:      '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94z"/>',
    tools:       '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94z"/>',
    edit:        '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4z"/>',
    clipboard:   '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/>',
    database:    '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
    satellite:   '<path d="M11 12 4 5"/><path d="M9 7 5 3 3 5l4 4"/><path d="m13 13 7 7"/><path d="m17 15 4 4-2 2-4-4"/><circle cx="18" cy="6" r="3"/>',
    cloud:       '<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z"/>',
    fire:        '<path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"/>',
    chat:        '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    email:       '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
    rocket:      '<path d="M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z"/><path d="m12 15-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z"/><path d="M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0"/><path d="M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"/>',
    appstore:    '<path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/>',
    lightning:   '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    laptop:      '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="2" y1="20" x2="22" y2="20"/>',
    brain:       '<path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2z"/>',
    folder:      '<path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>',
    'folder-open':'<path d="M6 14 4 22h16l-2-8z"/><path d="M22 14V8a2 2 0 0 0-2-2h-7l-2-2H4a2 2 0 0 0-2 2v14"/>',
    lightbulb:   '<path d="M9 18h6"/><path d="M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.2 1 2v.3h6v-.3c0-.8.4-1.5 1-2A7 7 0 0 0 12 2z"/>',
    document:    '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="16" y2="17"/>',
    pin:         '<line x1="12" y1="17" x2="12" y2="22"/><path d="M9 10V5h6v5l3 5H6z"/>',
    shield:      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    link:        '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
    'file-data': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>',
    bell:        '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.7 21a1.99 1.99 0 0 1-3.4 0"/>',
    megaphone:   '<path d="M3 11l18-5v12L3 14v-3z"/><path d="M11.6 16.8a3 3 0 1 1-5.8-1.6"/>',
    image:       '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/>',
    camera:      '<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>',
    scale:       '<path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1z"/><path d="M7 21h10"/><path d="M12 3v18"/><path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2"/>',
    money:       '<line x1="12" y1="1" x2="12" y2="23"/><path d="M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
    palette:     '<circle cx="13.5" cy="6.5" r=".5"/><circle cx="17.5" cy="10.5" r=".5"/><circle cx="8.5" cy="7.5" r=".5"/><circle cx="6.5" cy="12.5" r=".5"/><path d="M12 2a10 10 0 1 0 0 20 4 4 0 0 0 0-8 2 2 0 0 1-2-2 2 2 0 0 1 2-2h2a6 6 0 0 0 0-8z"/>',
    robot:       '<rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/>',
    heart:       '<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>',
    warning:     '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    help:        '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    add:         '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
    door:        '<path d="M18 20V6a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v14"/><path d="M2 20h20"/><path d="M14 12v.01"/>',
    search:      '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    gamepad:     '<line x1="6" y1="11" x2="10" y2="11"/><line x1="8" y1="9" x2="8" y2="13"/><line x1="15" y1="12" x2="15.01" y2="12"/><line x1="18" y1="10" x2="18.01" y2="10"/><path d="M17.32 5H6.68a4 4 0 0 0-3.978 3.59c-.006.052-.01.101-.017.152C2.604 9.416 2 14.456 2 16a3 3 0 0 0 3 3c1 0 1.5-.5 2-1l1.414-1.414A2 2 0 0 1 9.828 16h4.344a2 2 0 0 1 1.414.586L17 18c.5.5 1 1 2 1a3 3 0 0 0 3-3c0-1.545-.604-6.584-.685-7.258"/>',
    music:       '<path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/>',
    cart:        '<circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/>',
    book:        '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    lab:         '<path d="M9 2v6L4.6 16.7A2 2 0 0 0 6.3 19.6h11.4a2 2 0 0 0 1.7-2.9L15 8V2"/><line x1="9" y1="2" x2="15" y2="2"/>',
    star:        '<polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>',
    runner:      '<circle cx="13" cy="4" r="2"/><path d="m5 22 5-5 1-4 3 4 4-2"/><path d="m14 9 2-3 4 1-2 3"/>',
    movie:       '<rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/>',
    target:      '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    'file-code': '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="10 13 8 15 10 17"/><polyline points="14 13 16 15 14 17"/>',

    // Status indicators (used for ✅ ❌ ✓ ✕ ➕ etc.)
    check:        '<polyline points="20 6 9 17 4 12"/>',
    'check-circle':'<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
    close:        '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
    'x-circle':   '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    'circle-red': '<circle cx="12" cy="12" r="6" fill="currentColor"/>',
    'circle-green':'<circle cx="12" cy="12" r="6" fill="currentColor"/>',
    'circle-yellow':'<circle cx="12" cy="12" r="6" fill="currentColor"/>',
    'circle-blue':'<circle cx="12" cy="12" r="6" fill="currentColor"/>',

    // Common chrome not yet in EMOJI_TO_SEMANTIC
    refresh:     '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
    trash:       '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
    plug:        '<path d="M9 2v6"/><path d="M15 2v6"/><path d="M12 17v5"/><path d="M5 8h14a2 2 0 0 1 2 2v3a7 7 0 0 1-14 0v-3a2 2 0 0 1 2-2z"/>',
};

// Status-pill colour overrides for the four filled circles. The dots inherit
// currentColor by default, but the bare colour-named circles (🔴 🟢 🟡 🔵)
// carry meaning that shouldn't depend on the surrounding text colour.
const CLEAN_ICON_COLOURS = {
    'circle-red':    'var(--danger)',
    'circle-green':  'var(--success)',
    'circle-yellow': 'var(--warning)',
    'circle-blue':   'var(--info)',
};

// Extra emoji → semantic mappings the original table doesn't carry. Merged
// into EMOJI_TO_SEMANTIC at boot if it exists.
const CLEAN_EXTRA_EMOJI_MAP = {
    '🔄': 'refresh',
    '🗑': 'trash',
    '🗑️': 'trash',
    '🔌': 'plug',
    '✅': 'check-circle',
    '❌': 'x-circle',
    '✓': 'check',
    '✗': 'close',
    '✕': 'close',
    '➕': 'add',
    '🔴': 'circle-red',
    '🟢': 'circle-green',
    '🟡': 'circle-yellow',
    '🔵': 'circle-blue',
    '✏️': 'edit',
    '✏': 'edit',
    '✎': 'edit',
    '🔍': 'search',
};

function cleanIconAvailable(semantic) {
    return Object.prototype.hasOwnProperty.call(CLEAN_ICONS, semantic);
}

function cleanIconSvg(semantic) {
    const body = CLEAN_ICONS[semantic];
    if (!body) return '';
    const colour = CLEAN_ICON_COLOURS[semantic];
    const style = colour ? ` style="color:${colour}"` : '';
    return `<svg class="ws-icon-clean" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"${style}>${body}</svg>`;
}

let _cleanIconReplacing = false;

// Walk text nodes under `root`, replace any known emoji with an inline-svg
// <span class="ws-icon-clean-wrap">. Mirrors replaceEmojisWithPackIcons.
function translateEmojisToCleanSvg(root) {
    if (_cleanIconReplacing) return;
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return;
    _cleanIconReplacing = true;
    try {
        const textNodes = [];
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                const p = node.parentElement;
                if (!p) return NodeFilter.FILTER_REJECT;
                if (p.closest('[data-no-translate]')) return NodeFilter.FILTER_REJECT;
                if (p.classList?.contains('ws-icon-clean-wrap')) return NodeFilter.FILTER_REJECT;
                const tag = p.tagName;
                if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'INPUT' || tag === 'TEXTAREA') return NodeFilter.FILTER_REJECT;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        while (walker.nextNode()) textNodes.push(walker.currentNode);

        for (const textNode of textNodes) {
            replaceEmojiNodeWithCleanSvg(textNode);
        }
    } finally {
        _cleanIconReplacing = false;
    }
}

// For one text node, replace the first known emoji (working left-to-right
// across multiple passes) with an inline SVG span.
function replaceEmojiNodeWithCleanSvg(textNode) {
    let node = textNode;
    let safety = 50;
    while (node && node.parentNode && safety-- > 0) {
        const text = node.nodeValue;
        if (!text) return;
        let foundAt = -1;
        let foundEmoji = null;
        let foundSemantic = null;
        for (const [emoji, semantic] of Object.entries(EMOJI_TO_SEMANTIC)) {
            if (!cleanIconAvailable(semantic)) continue;
            const idx = text.indexOf(emoji);
            if (idx === -1) continue;
            if (foundAt === -1 || idx < foundAt) {
                foundAt = idx; foundEmoji = emoji; foundSemantic = semantic;
            }
        }
        if (foundAt === -1) return;

        const parent = node.parentNode;
        const before = text.substring(0, foundAt);
        const after = text.substring(foundAt + foundEmoji.length);

        const span = document.createElement('span');
        span.className = 'ws-icon-clean-wrap';
        span.setAttribute('data-emoji', foundEmoji);
        span.innerHTML = cleanIconSvg(foundSemantic);

        if (before) parent.insertBefore(document.createTextNode(before), node);
        parent.insertBefore(span, node);
        if (after) {
            const afterNode = document.createTextNode(after);
            parent.insertBefore(afterNode, node);
            parent.removeChild(node);
            node = afterNode;
        } else {
            parent.removeChild(node);
            return;
        }
    }
}

let _cleanIconObserver = null;

function observeForCleanIcons() {
    if (_cleanIconObserver) return;
    _cleanIconObserver = new MutationObserver((mutations) => {
        if (_cleanIconReplacing) return;
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (node.closest?.('[data-no-translate]')) continue;
                    if (node.classList?.contains('ws-icon-clean-wrap')) continue;
                    translateEmojisToCleanSvg(node);
                } else if (node.nodeType === Node.TEXT_NODE) {
                    if (node.parentElement?.closest('[data-no-translate]')) continue;
                    replaceEmojiNodeWithCleanSvg(node);
                }
            }
        }
    });
    _cleanIconObserver.observe(document.body, { childList: true, subtree: true });
}

// Merge the extra emoji mappings into EMOJI_TO_SEMANTIC after app.js has
// defined that constant. Call from initIconTheme before walking the DOM.
function mergeCleanEmojiMappings() {
    if (typeof EMOJI_TO_SEMANTIC === 'undefined') return;
    for (const [emoji, semantic] of Object.entries(CLEAN_EXTRA_EMOJI_MAP)) {
        if (!(emoji in EMOJI_TO_SEMANTIC)) EMOJI_TO_SEMANTIC[emoji] = semantic;
    }
}
