// Cloudflare Pages Function
// File path /functions/stripe-webhook.js maps to:
//   POST https://otomojp.app/stripe-webhook
//
// Set these as Environment Variables in the Cloudflare Pages
// project (Settings → Environment variables) — NOT in this file:
//   STRIPE_WEBHOOK_SECRET     (from Stripe → Developers → Webhooks)
//   SUPABASE_URL              (same value as the client-side config)
//   SUPABASE_SERVICE_ROLE_KEY (Supabase → Settings → API — SECRET, server-only)

export async function onRequestPost(context) {
  const { request, env } = context;

  const payload = await request.text();
  const sigHeader = request.headers.get('stripe-signature');

  const valid = await verifyStripeSignature(payload, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    return new Response('Invalid signature', { status: 400 });
  }

  const event = JSON.parse(payload);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const email = session.customer_details?.email || session.customer_email;

    if (email) {
      const res = await fetch(`${env.SUPABASE_URL}/rest/v1/profiles?on_conflict=email`, {
        method: 'POST',
        headers: {
          apikey: env.SUPABASE_SERVICE_ROLE_KEY,
          Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'resolution=merge-duplicates',
        },
        body: JSON.stringify({
          email: email.toLowerCase(),
          is_premium: true,
          stripe_customer_id: session.customer || null,
          updated_at: new Date().toISOString(),
        }),
      });

      if (!res.ok) {
        console.log('Supabase upsert failed', res.status, await res.text());
        return new Response('Supabase write failed', { status: 500 });
      }
    }
  }

  return new Response('ok', { status: 200 });
}

async function verifyStripeSignature(payload, sigHeader, secret) {
  if (!sigHeader || !secret) return false;

  const parts = Object.fromEntries(
    sigHeader.split(',').map((p) => p.split('='))
  );
  if (!parts.t || !parts.v1) return false;

  const signedPayload = `${parts.t}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuffer = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(signedPayload)
  );
  const expected = [...new Uint8Array(sigBuffer)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return expected === parts.v1;
}
