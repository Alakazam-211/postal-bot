const PRICE_CENTS = 999;
const PRODUCT = "Postal Unlimited";

function originOf(req) {
  const proto = (req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = (req.headers["x-forwarded-host"] || req.headers.host || "www.postal.bot")
    .split(",")[0]
    .trim();
  return `${proto}://${host}`;
}

function normalizeHost(raw) {
  let s = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "");
  if (!s) return "";
  if (!s.includes(".")) s = `${s}.postal.bot`;
  if (!/^[a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?\.postal\.bot$/.test(s)) return "";
  const label = s.slice(0, s.indexOf("."));
  if (label.length < 3) return "";
  return s;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      resolve(req.body);
      return;
    }
    if (typeof req.body === "string") {
      resolve(Object.fromEntries(new URLSearchParams(req.body)));
      return;
    }
    let d = "";
    req.on("data", (c) => {
      d += c;
    });
    req.on("end", () => {
      const ct = String(req.headers["content-type"] || "");
      if (ct.includes("json")) {
        try {
          resolve(JSON.parse(d || "{}"));
        } catch {
          resolve({});
        }
      } else {
        resolve(Object.fromEntries(new URLSearchParams(d)));
      }
    });
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.statusCode = 405;
    res.setHeader("Allow", "POST");
    res.end("POST only");
    return;
  }
  const body = await readBody(req);
  const host = normalizeHost(body.host || body.subdomain || "");
  if (!host) {
    res.statusCode = 400;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end("Need a label.postal.bot host (3+ char label).");
    return;
  }

  const origin = originOf(req);
  const paymentLink = (process.env.STRIPE_PAYMENT_LINK || "").trim();
  const secret = (process.env.STRIPE_SECRET_KEY || "").trim();

  if (!secret && paymentLink) {
    const url = new URL(paymentLink);
    url.searchParams.set("client_reference_id", host);
    res.statusCode = 303;
    res.setHeader("Location", url.toString());
    res.end();
    return;
  }

  if (!secret) {
    res.statusCode = 503;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Postal pay</title>
<style>body{font:17px/1.5 Palatino,serif;background:#12110f;color:#e8e4d9;margin:2rem}</style>
</head><body>
<h1>Payment portal is ready</h1>
<p>Set <code>STRIPE_SECRET_KEY</code> (or <code>STRIPE_PAYMENT_LINK</code>) on the Vercel project to take live $9.99/year charges for <strong>${host}</strong>.</p>
<p><a href="/pay" style="color:#d4c4a0">Back</a></p>
</body></html>`);
    return;
  }

  const params = new URLSearchParams();
  params.set("mode", "subscription");
  params.set("success_url", `${origin}/paid?session_id={CHECKOUT_SESSION_ID}`);
  params.set("cancel_url", `${origin}/pay`);
  params.set("client_reference_id", host);
  params.set("metadata[host]", host);
  params.set("subscription_data[metadata][host]", host);
  params.set("line_items[0][quantity]", "1");
  params.set("line_items[0][price_data][currency]", "usd");
  params.set("line_items[0][price_data][unit_amount]", String(PRICE_CENTS));
  params.set("line_items[0][price_data][recurring][interval]", "year");
  params.set("line_items[0][price_data][product_data][name]", PRODUCT);
  params.set(
    "line_items[0][price_data][product_data][description]",
    `Unlimited Postal messages on ${host}`
  );

  const auth = Buffer.from(`${secret}:`).toString("base64");
  const stripe = await fetch("https://api.stripe.com/v1/checkout/sessions", {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
  });
  const data = await stripe.json();
  if (!stripe.ok || !data.url) {
    res.statusCode = 502;
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.end((data && data.error && data.error.message) || "Stripe checkout failed");
    return;
  }
  res.statusCode = 303;
  res.setHeader("Location", data.url);
  res.end();
};

module.exports.normalizeHost = normalizeHost;
