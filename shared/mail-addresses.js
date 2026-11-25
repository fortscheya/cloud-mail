// Raw RFC address headers are parsed by PostalMime on receipt. This module handles
// its structured mailboxes and their stored JSON form in both server and browser.
function normalizeAddress(value) {
    if (typeof value !== 'string' || /[\x00-\x1f\x7f]/.test(value)) return '';
    const address = value.trim();
    const at = address.lastIndexOf('@');
    const local = address.slice(0, at);
    const domain = address.slice(at + 1);
    if (at < 1 || new TextEncoder().encode(local).length > 64 || address.length > 254) return '';
    const quoted = /^"(?:[^"\\\r\n]|\\[^\r\n])*"$/.test(local);
    if (!quoted && (!/^[^\s@()<>,:;\[\]"\\]+$/u.test(local) ||
        local.startsWith('.') || local.endsWith('.') || local.includes('..'))) return '';
    if (!domain || /[\s/:?#@\[\]\\%]/u.test(domain)) return '';
    let hostname = domain.toLowerCase();
    if (/[^\x00-\x7f]/.test(domain)) {
        try { hostname = new URL(`https://${domain}`).hostname; } catch { return ''; }
    }
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(hostname)) return '';
    const normalized = `${local}@${hostname}`;
    return new TextEncoder().encode(normalized).length <= 254 ? normalized : '';
}

export function normalizeMailboxes(value) {
    if (typeof value === 'string') {
        try { value = JSON.parse(value); } catch { value = [{ address: value }]; }
    }
    const pending = (Array.isArray(value) ? [...value] : [value]).reverse();
    const mailboxes = [];
    const seen = new Set();
    while (pending.length) {
        const item = pending.pop();
        if (Array.isArray(item?.group)) {
            pending.push(...[...item.group].reverse());
            continue;
        }
        const address = normalizeAddress(typeof item === 'string' ? item : item?.address);
        // Domains are case-insensitive; local parts can identify distinct mailboxes.
        if (!address || seen.has(address)) continue;
        seen.add(address);
        const name = typeof item?.name === 'string' ? item.name.replace(/[\r\n\0]/g, ' ').trim() : '';
        mailboxes.push({ address, name });
    }
    return mailboxes;
}

export function getReplyRecipients(email, userId) {
    // Continuing one's own sent message targets its original To list, not self.
    if (email.type === 1 && email.userId === userId) {
        return normalizeMailboxes(email.recipient).map(item => item.address);
    }
    const replyTo = normalizeMailboxes(email.replyTo);
    const targets = replyTo.length ? replyTo : normalizeMailboxes([{ address: email.sendEmail }]);
    return targets.map(item => item.address);
}
