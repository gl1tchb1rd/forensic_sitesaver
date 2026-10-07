// Copyright (C) 2026 Forensic SiteSaver contributors
// SPDX-License-Identifier: GPL-3.0-or-later
// Fixed, locally supplied controller: DOM changes only, no site code evaluation.
(() => {
    'use strict';
    const prefix = 'data-forensic-sitesaver-menu-';
    const controls = Array.from(document.querySelectorAll(`[${prefix}controls]`));
    const properties = ['display', 'visibility', 'opacity', 'pointer-events', 'transform', 'max-height', 'height'];
    const records = [];
    const byControl = new Map();
    const mouseHover = window.matchMedia('(hover: hover) and (pointer: fine)');
    for (const panel of document.querySelectorAll(`[${prefix}panel]`)) {
        const key = panel.getAttribute(`${prefix}panel`);
        const triggers = controls.filter(control => control.getAttribute(`${prefix}controls`) === key);
        if (!triggers.length) continue;
        const computed = getComputedStyle(panel);
        const expanded = triggers.find(control => control.hasAttribute('aria-expanded'));
        const record = {
            panel, triggers,
            open: expanded ? expanded.getAttribute('aria-expanded') === 'true' :
                !panel.hidden && computed.display !== 'none' && computed.visibility !== 'hidden' && computed.opacity !== '0',
            hoverOpened: false,
            active: true,
            hidden: panel.hidden,
            ariaHidden: panel.getAttribute('aria-hidden'),
            styles: properties.map(property => [property, panel.style.getPropertyValue(property), panel.style.getPropertyPriority(property)]),
            classes: ['show', 'is-open'].map(name => [name, panel.classList.contains(name)])
        };
        records.push(record);
        triggers.forEach(control => byControl.set(control, record));
    }

    function restore(record) {
        record.panel.hidden = record.hidden;
        if (record.ariaHidden === null) record.panel.removeAttribute('aria-hidden');
        else record.panel.setAttribute('aria-hidden', record.ariaHidden);
        for (const [property, value, priority] of record.styles) {
            if (value) record.panel.style.setProperty(property, value, priority);
            else record.panel.style.removeProperty(property);
        }
        for (const [name, present] of record.classes) record.panel.classList.toggle(name, present);
    }

    function render(record) {
        // Hidden responsive toggles leave the site's desktop navigation alone.
        record.active = record.triggers.some(control => getComputedStyle(control).display !== 'none');
        restore(record);
        if (!record.active) return;
        const panel = record.panel;
        panel.hidden = !record.open;
        panel.setAttribute('aria-hidden', String(!record.open));
        for (const control of record.triggers) {
            control.setAttribute('aria-expanded', String(record.open));
            control.classList.toggle('is-active', record.open);
        }
        panel.classList.toggle('show', record.open);
        panel.classList.toggle('is-open', record.open);
        if (record.open) {
            const computed = getComputedStyle(panel);
            panel.style.setProperty('display', computed.display === 'none' ? 'block' : computed.display, 'important');
            panel.style.setProperty('visibility', 'visible', 'important');
            panel.style.setProperty('opacity', '1', 'important');
            panel.style.setProperty('pointer-events', 'auto', 'important');
            panel.style.setProperty('transform', 'none', 'important');
            panel.style.setProperty('max-height', 'none', 'important');
            if (computed.height === '0px') panel.style.setProperty('height', 'auto', 'important');
        } else {
            panel.style.setProperty('display', 'none', 'important');
        }
    }

    function close(record) {
        record.open = false;
        record.hoverOpened = false;
        render(record);
        // Closing a parent also resets nested dropdowns.
        for (const child of records) {
            if (child !== record && record.panel.contains(child.panel)) {
                child.open = false;
                child.hoverOpened = false;
                render(child);
            }
        }
    }

    function open(record) {
        for (const other of records) {
            // Independent dropdowns close; nested parent menus stay open.
            if (other !== record && other.active && other.open &&
                !other.panel.contains(record.triggers[0]) && !record.panel.contains(other.triggers[0])) close(other);
        }
        record.open = true;
        render(record);
    }

    function toggle(record) {
        // A mouse entering a fragment toggle can open it immediately before
        // its click. Treat that first click as an explicit opening.
        if (record.hoverOpened) { record.hoverOpened = false; render(record); return; }
        if (record.open) close(record);
        else open(record);
    }

    for (const record of records) {
        const key = record.panel.getAttribute(`${prefix}panel`);
        const region = document.querySelector(`[${prefix}hover-region="${key}"]`);
        if (!region) continue;
        for (const link of region.querySelectorAll(`[${prefix}hover-trigger="${key}"]`)) {
            link.addEventListener('pointerenter', event => {
                if (event.pointerType !== 'mouse' || !mouseHover.matches || record.open) return;
                open(record);
                record.hoverOpened = true;
            });
        }
        region.addEventListener('pointerleave', event => {
            if (event.pointerType === 'mouse' && mouseHover.matches) close(record);
        });
    }

    document.addEventListener('click', event => {
        if (!(event.target instanceof Element)) return;
        const trigger = event.target.closest(`[${prefix}controls]`);
        if (byControl.has(trigger)) {
            event.preventDefault();
            toggle(byControl.get(trigger));
            return;
        }
        for (const record of records) {
            if (record.active && record.open && !record.panel.contains(event.target) &&
                !record.triggers.some(control => control.contains(event.target))) close(record);
        }
    });

    document.addEventListener('keydown', event => {
        if (!(event.target instanceof Element)) return;
        const trigger = event.target.closest(`[${prefix}controls]`);
        if (byControl.has(trigger) && trigger.tagName !== 'BUTTON' && ['Enter', ' '].includes(event.key)) {
            event.preventDefault();
            toggle(byControl.get(trigger));
        } else if (event.key === 'Escape') {
            const open = records.filter(record => record.active && record.open);
            const containing = open.filter(record => record.panel.contains(event.target) || record.triggers.includes(trigger));
            const record = containing.reverse()[0] || open.reverse()[0];
            if (record) {
                event.preventDefault();
                close(record);
                record.triggers[0].focus();
            }
        }
    });
    window.addEventListener('resize', () => records.forEach(render));
    records.forEach(render);
})();
