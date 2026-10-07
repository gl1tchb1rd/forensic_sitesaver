// Copyright (C) 2026 Forensic SiteSaver contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Original destinations are displayed/copied as text, never opened or evaluated.
(() => {
    'use strict';
    const prefix = 'data-forensic-sitesaver-link-';
    const selector = `[${prefix}target]`;
    const links = new Set(document.querySelectorAll(selector));
    if (!links.size) return;
    const descriptions = new Map(Array.from(links, link => [link, link.getAttribute('aria-describedby')]));
    const root = document.body || document.documentElement;
    const uniqueId = name => {
        let id = `forensic-sitesaver-link-${name}`;
        while (document.getElementById(id)) id += '-local';
        return id;
    };
    const element = (name, text) => {
        const node = document.createElement(name);
        if (text) node.textContent = text;
        return node;
    };
    const tooltip = element('div');
    tooltip.id = uniqueId('tooltip');
    tooltip.setAttribute(`${prefix}ui`, 'tooltip');
    tooltip.setAttribute('role', 'tooltip');
    tooltip.hidden = true;
    root.append(tooltip);
    const dialog = element('dialog');
    dialog.setAttribute(`${prefix}ui`, 'dialog');
    const heading = element('h2', 'Ursprüngliches Linkziel');
    heading.id = uniqueId('heading');
    dialog.setAttribute('aria-labelledby', heading.id);
    const description = element('p', 'Externe Links und Verbindungen sind gesperrt. Diese Zieladresse wird nicht aufgerufen.');
    description.id = uniqueId('description');
    dialog.setAttribute('aria-describedby', description.id);
    const label = element('label', 'Zieladresse');
    const address = element('textarea');
    address.id = uniqueId('address');
    address.readOnly = true;
    address.rows = 3;
    label.htmlFor = address.id;
    const copy = element('button', 'URL kopieren');
    const close = element('button', 'Schließen');
    copy.type = close.type = 'button';
    const status = element('p');
    status.setAttribute('role', 'status');
    status.setAttribute('aria-live', 'polite');
    dialog.append(heading, description, label, address, copy, close, status);
    root.append(dialog);
    let tooltipLink = null;
    let opener = null;
    let generation = 0;

    function hideTooltip() {
        if (tooltipLink) {
            const original = descriptions.get(tooltipLink);
            if (original === null) tooltipLink.removeAttribute('aria-describedby');
            else tooltipLink.setAttribute('aria-describedby', original);
        }
        tooltipLink = null;
        tooltip.hidden = true;
    }

    function showTooltip(link) {
        if (dialog.open) return;
        hideTooltip();
        tooltipLink = link;
        tooltip.textContent = link.getAttribute('data-original-url') || '';
        const original = descriptions.get(link);
        link.setAttribute('aria-describedby', [original, tooltip.id].filter(Boolean).join(' '));
        tooltip.style.left = '8px';
        tooltip.style.top = '8px';
        tooltip.hidden = false;
        const bounds = link.getBoundingClientRect();
        const width = tooltip.offsetWidth;
        const height = tooltip.offsetHeight;
        tooltip.style.left = `${Math.max(8, Math.min(bounds.left, innerWidth - width - 8))}px`;
        const below = bounds.bottom + 8;
        tooltip.style.top = `${Math.max(8, below + height <= innerHeight - 8 ? below : bounds.top - height - 8)}px`;
    }

    function showDestination(link) {
        hideTooltip();
        opener = link;
        generation += 1;
        address.value = link.getAttribute('data-original-url') || '';
        status.textContent = '';
        if (!dialog.open) dialog.showModal();
        address.focus();
        address.select();
    }

    function dismiss() {
        generation += 1;
        dialog.close();
        if (opener && opener.isConnected) opener.focus();
        hideTooltip();
    }

    function source(event) {
        if (!(event.target instanceof Element)) return null;
        const link = event.target.closest(selector);
        return links.has(link) ? link : null;
    }

    for (const link of links) link.removeAttribute('title'); // Custom tooltip; saved HTML retains the title fallback.
    document.addEventListener('mouseover', event => {
        const link = source(event);
        if (link) showTooltip(link);
    });
    document.addEventListener('mouseout', event => {
        const link = source(event);
        if (link && !(event.relatedTarget instanceof Node && link.contains(event.relatedTarget)) &&
            document.activeElement !== link) hideTooltip();
    });
    document.addEventListener('focusin', event => {
        const link = source(event);
        if (link) showTooltip(link);
    });
    document.addEventListener('focusout', event => {
        if (source(event)) hideTooltip();
    });
    document.addEventListener('click', event => {
        const link = source(event);
        if (!link) return;
        event.preventDefault();
        event.stopPropagation();
        showDestination(link);
    }, true);
    document.addEventListener('keydown', event => {
        const link = source(event);
        if (link && ['Enter', ' '].includes(event.key)) {
            event.preventDefault();
            event.stopPropagation();
            showDestination(link);
        } else if (event.key === 'Escape') hideTooltip();
    }, true);
    dialog.addEventListener('keydown', event => {
        event.stopPropagation(); // Background menus must not react to dialog Escape.
        if (event.key === 'Escape') {
            event.preventDefault();
            dismiss();
        }
    });
    dialog.addEventListener('cancel', event => {
        event.preventDefault();
        dismiss();
    });
    dialog.addEventListener('click', event => {
        event.stopPropagation();
        if (event.target === dialog) {
            const bounds = dialog.getBoundingClientRect();
            if (event.clientX < bounds.left || event.clientX > bounds.right ||
                event.clientY < bounds.top || event.clientY > bounds.bottom) dismiss();
        }
    });
    close.addEventListener('click', dismiss);
    copy.addEventListener('click', async () => {
        const current = generation;
        const value = address.value;
        let copied = false;
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(value);
                copied = true;
            }
        } catch (_) { /* Fall back to selection and the local copy command. */ }
        if (current !== generation || !dialog.open) return;
        if (!copied) {
            address.focus();
            address.select();
            try { copied = document.execCommand('copy'); } catch (_) { /* Manual copy remains available. */ }
        }
        status.textContent = copied ? 'URL kopiert.' : 'Die URL ist markiert. Mit Strg+C bzw. ⌘C kopieren.';
    });
    function repositionTooltip() {
        const link = tooltipLink;
        if (!link) return;
        const bounds = link.getBoundingClientRect();
        if (bounds.bottom < 0 || bounds.top > innerHeight ||
            (document.activeElement !== link && !link.matches(':hover'))) hideTooltip();
        else showTooltip(link);
    }
    window.addEventListener('scroll', repositionTooltip, true);
    window.addEventListener('resize', repositionTooltip);
})();
