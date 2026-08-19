function isSessionId(id) {
  return (
    typeof id === "string" &&
    id.startsWith("cs_") &&
    id.length < 256 &&
    /^[A-Za-z0-9_-]+$/.test(id)
  );
}

module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "GET") {
    res.statusCode = 405;
    res.end(JSON.stringify({ error: "GET only" }));
    return;
  }
  const url = new URL(req.url, "https://www.postal.bot");
  const id = (url.searchParams.get("id") || url.searchParams.get("session_id") || "").trim();
  if (!isSessionId(id)) {
    res.statusCode = 400;
    res.end(JSON.stringify({ paid: false, error: "bad checkout session id" }));
    return;
  }
  const secret = (process.env.STRIPE_SECRET_KEY || "").trim();
  if (!secret) {
    res.statusCode = 503;
    res.end(JSON.stringify({ paid: false, error: "STRIPE_SECRET_KEY is not set" }));
    return;
  }
  const auth = Buffer.from(`${secret}:`).toString("base64");
  const stripe = await fetch(
    `https://api.stripe.com/v1/checkout/sessions/${encodeURIComponent(id)}?expand[]=subscription`,
    { headers: { Authorization: `Basic ${auth}` } }
  );
  const data = await stripe.json();
  if (!stripe.ok) {
    res.statusCode = stripe.status === 404 ? 404 : 502;
    res.end(
      JSON.stringify({
        paid: false,
        error: (data && data.error && data.error.message) || "stripe error",
      })
    );
    return;
  }
  const paid = data.payment_status === "paid" || data.status === "complete";
  const host =
    (data.metadata && data.metadata.host) ||
    data.client_reference_id ||
    (data.subscription && data.subscription.metadata && data.subscription.metadata.host) ||
    "";
  let until_unix = null;
  if (data.subscription && typeof data.subscription === "object") {
    until_unix = data.subscription.current_period_end || null;
  }
  res.statusCode = 200;
  res.end(
    JSON.stringify({
      paid,
      host,
      until_unix,
      id: data.id || id,
    })
  );
};
