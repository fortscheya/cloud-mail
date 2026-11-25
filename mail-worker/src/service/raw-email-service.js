import { and, eq } from 'drizzle-orm';
import orm from '../entity/orm';
import email from '../entity/email';
import r2Service from './r2-service';
import BizError from '../error/biz-error';
import { t } from '../i18n/i18n';

const rawKeyPattern = /^raw-emails\/[a-f0-9]{32}\.eml$/;
const storageTypes = new Set(['KV', 'R2', 'S3']);

const rawEmailService = {
    async store(c, bytes) {
        const rawStorage = await r2Service.storageType(c);
        const rawKey = `raw-emails/${crypto.randomUUID().replace(/-/g, '')}.eml`;
        await r2Service.putObj(c, rawKey, bytes, {
            contentType: 'message/rfc822',
            contentDisposition: 'attachment; filename="message.eml"',
            cacheControl: 'private, no-store'
        }, rawStorage);
        return { rawKey, rawStorage };
    },

    // Archive before inserting: a failed archive must not create an accepted mail.
    async insert(c, values, bytes) {
        const archive = await this.store(c, bytes);
        try {
            return await orm(c).insert(email).values({ ...values, ...archive }).returning().get();
        } catch (error) {
            try { await this.remove(c, [archive]); } catch { console.error('Failed to clean up unlinked raw email'); }
            throw error;
        }
    },

    async download(c, emailId, userId) {
        emailId = Number(emailId);
        if (!Number.isSafeInteger(emailId) || emailId <= 0) throw new BizError(t('rawEmailUnavailable'), 404);
        const admin = c.get('user')?.email === c.env.admin;
        const row = await orm(c).select({ rawKey: email.rawKey, rawStorage: email.rawStorage }).from(email)
            .where(and(eq(email.emailId, emailId), admin ? undefined : eq(email.userId, userId))).get();
        if (!row || !rawKeyPattern.test(row.rawKey) || !storageTypes.has(row.rawStorage)) {
            throw new BizError(t('rawEmailUnavailable'), 404);
        }
        let object;
        try {
            object = await r2Service.getObj(c, row.rawKey, row.rawStorage);
        } catch (error) {
            if (error?.$metadata?.httpStatusCode !== 404 && !['NoSuchKey', 'NotFound'].includes(error?.name)) throw error;
        }
        if (!object) throw new BizError(t('rawEmailUnavailable'), 404);
        return new Response(object.body, { headers: {
            'Content-Type': 'message/rfc822',
            'Content-Disposition': `attachment; filename="email-${emailId}.eml"`,
            'Cache-Control': 'private, no-store',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'sandbox'
        } });
    },

    async remove(c, rows) {
        for (const storage of storageTypes) {
            const keys = rows.filter(row => row.rawStorage === storage && rawKeyPattern.test(row.rawKey))
                .map(row => row.rawKey);
            for (let offset = 0; offset < keys.length; offset += 1000) {
                await r2Service.delete(c, keys.slice(offset, offset + 1000), storage);
            }
        }
    },

    async removeWhere(c, condition) {
        const rows = await orm(c).select({ rawKey: email.rawKey, rawStorage: email.rawStorage }).from(email).where(condition).all();
        await this.remove(c, rows);
    }
};

export default rawEmailService;
