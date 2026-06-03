interface Env {
  TELEGRAM_BOT_TOKEN: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    
    // CORS Headers
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (url.pathname === "/api/auth" && request.method === "POST") {
      try {
        const { initData } = await request.json() as { initData: string };
        if (!initData) {
          return new Response(JSON.stringify({ success: false, error: "Missing initData" }), { status: 400, headers: corsHeaders });
        }

        const isValid = await verifyTelegramInitData(initData, env.TELEGRAM_BOT_TOKEN);
        
        if (!isValid) {
          return new Response(JSON.stringify({ success: false, error: "Unauthorized data modification" }), { status: 401, headers: corsHeaders });
        }

        // Parse user data from initData safely
        const params = new URLSearchParams(initData);
        const userRaw = params.get("user");
        const user = userRaw ? JSON.parse(userRaw) : null;

        return new Response(JSON.stringify({ success: true, user }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (err: any) {
        return new Response(JSON.stringify({ success: false, error: err.message }), { status: 500, headers: corsHeaders });
      }
    }

    return new Response("Not Found", { status: 404, headers: corsHeaders });
  }
};

// Cryptographic validation using Web Crypto API
async function verifyTelegramInitData(initData: string, botToken: string): Promise<boolean> {
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return false;

  // Delete hash from checking chain
  params.delete("hash");

  // Sort components alphabetically
  const sortedParams = Array.from(params.entries())
    .map(([key, value]) => `${key}=${value}`)
    .sort()
    .join("\n");

  const encoder = new TextEncoder();
  
  // Create secret key: HMAC_SHA256(botToken, "WebAppData")
  const webAppDataKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode("WebAppData"),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  const secretKeyBuffer = await crypto.subtle.sign(
    "HMAC",
    webAppDataKey,
    encoder.encode(botToken)
  );

  const secretKey = await crypto.subtle.importKey(
    "raw",
    secretKeyBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  // Calculate signature
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    secretKey,
    encoder.encode(sortedParams)
  );

  // Convert to hex
  const calculatedHash = Array.from(new Uint8Array(signatureBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

  return calculatedHash === hash;
}
