import resendService from '../service/resend-service';
import app from '../hono/hono';

// Resend webhook 验签（Svix）：签名密钥是 Resend 后台给该端点生成的
// RESEND_WEBHOOK_SECRET（whsec_ 开头），与站内其他密钥分离。
// 未配置或验签失败一律 401；该端点不能用登录 JWT（Resend 调不来），
// 所以验签必须在 handler 里做，而不是靠 security.js 的 exclude 移除。
const encoder = new TextEncoder();

function base64Decode(str) {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) str += '=';
	return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function timingSafeEqualBytes(x, y) {
	if (x.length !== y.length) return false;
	let diff = 0;
	for (let i = 0; i < x.length; i += 1) diff |= x[i] ^ y[i];
	return diff === 0;
}

async function verifySvix(c, rawBody) {
	const secret = c.env.resend_webhook_secret || '';
	if (!secret) return false;
	const svixId = c.req.header('svix-id') || '';
	const svixTimestamp = c.req.header('svix-timestamp') || '';
	const svixSignature = c.req.header('svix-signature') || '';
	if (!svixId || !svixTimestamp || !svixSignature) return false;

	// 5 分钟时间窗，防重放
	const now = Math.floor(Date.now() / 1000);
	const ts = Number(svixTimestamp);
	if (!Number.isSafeInteger(ts) || Math.abs(now - ts) > 300) return false;

	const keyBytes = base64Decode(secret.replace(/^whsec_/, ''));
	const key = await crypto.subtle.importKey(
		'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
	);
	const signed = encoder.encode(`${svixId}.${svixTimestamp}.${rawBody}`);
	const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, signed));

	// svix-signature 可能是空格分隔的多个 v1 签名，任一命中即通过
	for (const part of svixSignature.split(' ')) {
		const [version, sig] = part.split(',');
		if (version !== 'v1' || !sig) continue;
		try {
			if (timingSafeEqualBytes(base64Decode(sig), expected)) return true;
		} catch {
			continue;
		}
	}
	return false;
}

app.post('/webhooks', async (c) => {
	try {
		const rawBody = await c.req.text();
		if (!(await verifySvix(c, rawBody))) {
			return c.text('invalid signature', 401);
		}
		await resendService.webhooks(c, JSON.parse(rawBody));
		return c.text('success', 200)
	} catch (e) {
		return c.text(e.message, 500)
	}
})
