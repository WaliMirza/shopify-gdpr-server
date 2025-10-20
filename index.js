const express = require("express");
const crypto = require("crypto");
const path = require("path");

const app = express();

app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);

function verifyHmac(req, res, next) {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
  if (!hmacHeader) {
    return res.status(401).send("Unauthorized - Missing HMAC");
  }

  const generatedHmac = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(req.rawBody, "utf8")
    .digest("base64");

  if (generatedHmac === hmacHeader) {
    next();
  } else {
    console.error("❌ Invalid HMAC");
    res.status(401).send("Unauthorized");
  }
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.post("/webhooks/customers/data_request", verifyHmac, (req, res) => {
  console.log("📩 customers/data_request webhook received");
  res.sendStatus(200);
});

app.post("/webhooks/customers/redact", verifyHmac, (req, res) => {
  console.log("🧹 customers/redact webhook received");
  res.sendStatus(200);
});

app.post("/webhooks/shop/redact", verifyHmac, (req, res) => {
  console.log("🧽 shop/redact webhook received");
  res.sendStatus(200);
});

// ✅ Add this route for Shopify test webhook
app.post("/webhooks", (req, res) => {
  const hmacHeader = req.get("X-Shopify-Hmac-Sha256");
  if (!hmacHeader) {
    return res.status(401).send("Unauthorized - Missing HMAC");
  }

  const generatedHmac = crypto
    .createHmac("sha256", process.env.SHOPIFY_API_SECRET)
    .update(req.rawBody || "", "utf8")
    .digest("base64");

  if (generatedHmac === hmacHeader) {
    res.sendStatus(200);
  } else {
    res.status(401).send("Unauthorized");
  }
});

app.listen(3000, () =>
  console.log("✅ GDPR webhook server running on port 3000")
);
