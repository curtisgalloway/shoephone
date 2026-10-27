// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0
// Stubs for the browser objects the approve page's script touches while it
// loads, so a harness can run it under node and call its top-level functions.
const makeEl = () => ({
  classList: {toggle() {}, add() {}, remove() {}}, style: {}, children: [],
  append() {}, replaceChildren() {}, setAttribute() {},
});
const els = {};
globalThis.document = {
  getElementById: id => (els[id] ??= makeEl()),
  createElement: () => makeEl(),
  addEventListener() {},
  hidden: false,
};
Object.defineProperty(globalThis, 'navigator', {value: {}, configurable: true});
globalThis.fetch = () => Promise.reject(new Error('no daemon in the harness'));
globalThis.setInterval = () => 0;
globalThis.setTimeout = () => 0;
