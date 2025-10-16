const express = require("express");
const crypto = require("crypto");

const app = express();
app.use(express.json({ verify: (req, res, buf) => (req.rawBody = buf) }));

function verifyHmac(req, res, next) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
  const generatedHmac = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(req.rawBody, "utf8")
    .digest("base64");

  if (generatedHmac === hmacHeader) next();
  else res.status(401).send("Unauthorized");
}

app.post("/webhooks/customers/data_request", verifyHmac, (req, res) => res.sendStatus(200));
app.post("/webhooks/customers/redact", verifyHmac, (req, res) => res.sendStatus(200));
app.post("/webhooks/shop/redact", verifyHmac, (req, res) => res.sendStatus(200));

app.listen(3000, () => console.log("GDPR webhooks server running on port 3000"));
