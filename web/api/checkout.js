/** Billing is K2 Web / k2.dev (Connect SKU). Postal does not take cards. */
module.exports = async (req, res) => {
  res.statusCode = 303;
  res.setHeader("Location", "https://k2.dev/signup");
  res.end();
};
