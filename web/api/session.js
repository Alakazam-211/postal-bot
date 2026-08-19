/** Stripe sessions are on K2 Web. Postal does not verify checkout ids. */
module.exports = async (req, res) => {
  res.statusCode = 410;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(
    JSON.stringify({
      paid: false,
      error: "billing is the k2.dev account; see https://www.postal.bot/account",
    })
  );
};
