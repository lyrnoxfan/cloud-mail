const encoder = new TextEncoder();
const decoder = new TextDecoder();

const base64url = (input) => {
	const str = btoa(String.fromCharCode(...new Uint8Array(input)));
	return str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

const base64urlDecode = (str) => {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) str += '=';
	return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

// 密钥派生：不同用途用不同密钥，Telegram 邮件链接 token 即使泄露也
// 不能冒充登录 token，反之亦然。派生输入与用途字符串绑定。
async function deriveKeyBytes(c, purpose) {
	const master = await crypto.subtle.importKey(
		'raw',
		encoder.encode(c.env.jwt_secret),
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);
	const derived = await crypto.subtle.sign(
		'HMAC',
		master,
		encoder.encode(`cloud-mail/key/v1:${purpose}`)
	);
	return new Uint8Array(derived);
}

async function importHmacKey(rawBytes) {
	return crypto.subtle.importKey(
		'raw',
		rawBytes,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign', 'verify']
	);
}

// Telegram 邮件链接 token：仅用于 /telegram/getEmail，带用途标记、
// 归属 userId、7 天有效期。用派生密钥签名，与登录 token 密钥隔离。
const TELEGRAM_TOKEN_PURPOSE = 'telegram-email';
const TELEGRAM_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;

const jwtUtils = {
	async generateTelegramToken(c, { emailId, userId }) {
		const header = { alg: 'HS256', typ: 'JWT' };
		const now = Math.floor(Date.now() / 1000);
		const fullPayload = {
			emailId, userId, purpose: TELEGRAM_TOKEN_PURPOSE,
			iat: now, exp: now + TELEGRAM_TOKEN_TTL_SECONDS
		};
		const headerStr = base64url(encoder.encode(JSON.stringify(header)));
		const payloadStr = base64url(encoder.encode(JSON.stringify(fullPayload)));
		const data = `${headerStr}.${payloadStr}`;
		const key = await importHmacKey(await deriveKeyBytes(c, TELEGRAM_TOKEN_PURPOSE));
		const signatureStr = base64url(await crypto.subtle.sign('HMAC', key, encoder.encode(data)));
		return `${data}.${signatureStr}`;
	},

	async verifyTelegramToken(c, token) {
		try {
			const [headerB64, payloadB64, signatureB64] = (token || '').split('.');
			if (!headerB64 || !payloadB64 || !signatureB64) return null;
			const data = `${headerB64}.${payloadB64}`;
			const key = await importHmacKey(await deriveKeyBytes(c, TELEGRAM_TOKEN_PURPOSE));
			const valid = await crypto.subtle.verify(
				'HMAC', key, base64urlDecode(signatureB64), encoder.encode(data)
			);
			if (!valid) return null;
			const payload = JSON.parse(decoder.decode(base64urlDecode(payloadB64)));
			const now = Math.floor(Date.now() / 1000);
			if (payload.purpose !== TELEGRAM_TOKEN_PURPOSE) return null;
			if (!payload.exp || payload.exp < now) return null;
			if (typeof payload.emailId !== 'number' || typeof payload.userId !== 'number') return null;
			return payload;
		} catch (err) {
			console.log(err);
			return null;
		}
	},

	async generateToken(c, payload, expiresInSeconds) {
		const header = {
			alg: 'HS256',
			typ: 'JWT'
		};

		const now = Math.floor(Date.now() / 1000);
		const exp = expiresInSeconds ? now + expiresInSeconds : undefined;

		const fullPayload = {
			...payload,
			iat: now,
			...(exp ? { exp } : {})
		};

		const headerStr = base64url(encoder.encode(JSON.stringify(header)));
		const payloadStr = base64url(encoder.encode(JSON.stringify(fullPayload)));
		const data = `${headerStr}.${payloadStr}`;

		const key = await crypto.subtle.importKey(
			'raw',
			encoder.encode(c.env.jwt_secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);

		const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
		const signatureStr = base64url(signature);

		return `${data}.${signatureStr}`;
	},

	async verifyToken(c, token) {
		try {
			const [headerB64, payloadB64, signatureB64] = token.split('.');

			if (!headerB64 || !payloadB64 || !signatureB64) return null;

			const data = `${headerB64}.${payloadB64}`;
			const key = await crypto.subtle.importKey(
				'raw',
				encoder.encode(c.env.jwt_secret),
				{ name: 'HMAC', hash: 'SHA-256' },
				false,
				['verify']
			);

			const valid = await crypto.subtle.verify(
				'HMAC',
				key,
				base64urlDecode(signatureB64),
				encoder.encode(data)
			);

			if (!valid) return null;

			const payloadJson = decoder.decode(base64urlDecode(payloadB64));
			const payload = JSON.parse(payloadJson);

			const now = Math.floor(Date.now() / 1000);
			if (payload.exp && payload.exp < now) return null;

			return payload;

		} catch (err) {
			console.log(err)
			return null;
		}
	}
};

export default jwtUtils;
