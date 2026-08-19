/** Paid labels: same K2 Connect Stripe portal. Postal does not take cards. */
module.exports = async (req, res) => {
  res.statusCode = 303;
  res.setHeader("Location", "https://k2.dev/pricing");
  res.end();
};
