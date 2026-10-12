
const { URL } = require("node:url");
const net = require("node:net");

// Common URL-shortening services.
// This list is illustrative, not exhaustive.
const SHORTENER_DOMAINS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
]);

// Common executable or potentially risky download extensions.
const RISKY_EXTENSIONS = new Set([
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".com",
    ".ps1",
    ".vbs",
    ".js",
    ".jar",
    ".hta",
    ".dll",
]);

// Brand domains used only for basic lookalike detection.
// Add more brands as needed.
const TRUSTED_BRAND_DOMAINS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "facebook.com",
    "instagram.com",
    "apple.com",
];

// Suspicious words are indicators, not proof of an attack.
const SUSPICIOUS_KEYWORDS = [
    "verify-account",
    "confirm-password",
    "password-reset",
    "login-verify",
    "account-suspended",
    "claim-prize",
    "free-gift",
    "urgent-action",
    "wallet-connect",
    "security-alert",
];

// Calculate edit distance between two strings.
// Used to identify possible brand-name misspellings.
function editDistance(a, b) {
    const dp = Array.from(
        { length: a.length + 1 },
        () => Array(b.length + 1).fill(0)
    );

    for (let i = 0; i <= a.length; i++) {
        dp[i][0] = i;
    }

    for (let j = 0; j <= b.length; j++) {
        dp[0][j] = j;
    }

    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;

            dp[i][j] = Math.min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            );
        }
    }

    return dp[a.length][b.length];
}

// Check whether the hostname is a shortened-link domain.
function isShortenedURL(hostname) {
    return [...SHORTENER_DOMAINS].some(
        domain =>
            hostname === domain ||
            hostname.endsWith("." + domain)
    );
}

// Detect hostnames that imitate a known brand.
function detectLookalikeDomain(hostname) {
    const labels = hostname
        .toLowerCase()
        .split(".")
        .filter(Boolean);

    for (const brandDomain of TRUSTED_BRAND_DOMAINS) {
        const brand = brandDomain.split(".")[0];

        // Ignore an exact official hostname or its subdomains.
        if (
            hostname === brandDomain ||
            hostname.endsWith("." + brandDomain)
        ) {
            continue;
        }

        for (const label of labels) {
            // Ignore very short or unrelated labels.
            if (label.length < 4) continue;

            const distance = editDistance(label, brand);

            // Conservative heuristic for simple misspellings.
            if (
                distance > 0 &&
                distance <= 2 &&
                Math.abs(label.length - brand.length) <= 2
            ) {
                return `Possible ${brand} impersonation in hostname`;
            }
        }
    }

    return null;
}

// Main URL validation function.
function validateURL(input) {
    const findings = [];
    let score = 0;

    function flag(message, points = 1) {
        findings.push(message);
        score += points;
    }

    // Input validation.
    if (typeof input !== "string" || !input.trim()) {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["URL is required"],
        };
    }

    const value = input.trim();

    // Avoid accepting hidden whitespace or control characters.
    if (/[\u0000-\u0020\u007f]/.test(value)) {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["URL contains whitespace or control characters"],
        };
    }

    // Require an explicit HTTP(S) URL.
    if (!/^https?:\/\//i.test(value)) {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["Only absolute HTTP or HTTPS URLs are accepted"],
        };
    }

    let url;

    try {
        url = new URL(value);
    } catch {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["URL format is invalid"],
        };
    }

    // Protocol validation.
    if (!["http:", "https:"].includes(url.protocol)) {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["Unsupported URL protocol"],
        };
    }

    // Reject URLs containing username/password credentials.
    if (url.username || url.password) {
        flag("URL contains embedded credentials", 4);
    }

    const hostname = url.hostname
        .toLowerCase()
        .replace(/\.$/, "");

    if (!hostname) {
        return {
            valid: false,
            status: "INVALID",
            score: 0,
            findings: ["Hostname is missing"],
        };
    }

    // Flag localhost and local/private network targets.
    // This is especially important if the application fetches URLs.
    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local")
    ) {
        flag("Hostname refers to a local network name", 3);
    }

    // Detect IPv4 and IPv6 literals.
    if (net.isIP(hostname)) {
        flag("URL uses an IP address instead of a domain name", 2);
    } else {
        // Flag single-label hosts and unusual hostname syntax.
        if (!hostname.includes(".")) {
            flag("Hostname has no public-style domain suffix", 2);
        }

        if (hostname.length > 253) {
            flag("Hostname is unusually long", 2);
        }

        if (hostname.includes("xn--")) {
            flag("Hostname contains internationalized/punycode labels", 1);
        }

        // Detect excessive subdomains.
        const labels = hostname.split(".");

        if (labels.length >= 5) {
            flag("Hostname contains many subdomain levels", 2);
        }

        // Basic brand-lookalike detection.
        const lookalike = detectLookalikeDomain(hostname);

        if (lookalike) {
            flag(lookalike, 4);
        }
    }

    // URL shorteners conceal the final destination.
    if (isShortenedURL(hostname)) {
        flag("URL uses a known URL-shortening service", 2);
    }

    // HTTP does not encrypt the connection.
    if (url.protocol === "http:") {
        flag("URL uses HTTP instead of HTTPS", 1);
    }

    const fullURL = decodeSafely(
        `${url.pathname}${url.search}`.toLowerCase()
    );

    // Look for suspicious wording in the path or query.
    for (const keyword of SUSPICIOUS_KEYWORDS) {
        if (fullURL.includes(keyword)) {
            flag(`Suspicious URL keyword detected: ${keyword}`, 2);
        }
    }

    // Flag unusually long URLs.
    if (value.length > 2048) {
        flag("URL is unusually long", 1);
    }

    // Flag repeated @ characters, which may confuse readers.
    if ((value.match(/@/g) || []).length > 0) {
        flag("URL contains an @ character; inspect the hostname carefully", 1);
    }

    // Detect nested URLs in common redirect parameters.
    const redirectParameters = [
        "url",
        "next",
        "target",
        "redirect",
        "redirect_url",
        "return",
        "returnurl",
        "continue",
        "dest",
        "destination",
    ];

    for (const parameter of redirectParameters) {
        const destination = url.searchParams.get(parameter);

        if (destination) {
            try {
                const decodedDestination = new URL(destination, url);

                if (
                    decodedDestination.origin !== url.origin &&
                    /^https?:$/.test(decodedDestination.protocol)
                ) {
                    flag(
                        `External destination found in "${parameter}" parameter`,
                        2
                    );
                }
            } catch {
                flag(
                    `Unparseable destination in "${parameter}" parameter`,
                    1
                );
            }
        }
    }

    // Detect potentially risky file downloads.
    const pathname = url.pathname.toLowerCase();
    const lastSegment = pathname.split("/").pop() || "";
    const extensionMatch = lastSegment.match(/\.[a-z0-9]+$/);

    if (
        extensionMatch &&
        RISKY_EXTENSIONS.has(extensionMatch[0])
    ) {
        flag(
            `Potentially risky download extension: ${extensionMatch[0]}`,
            3
        );
    }

    // Convert the score into a warning level.
    let status;

    if (score >= 6) {
        status = "HIGH RISK";
    } else if (score >= 3) {
        status = "SUSPICIOUS";
    } else if (score > 0) {
        status = "CAUTION";
    } else {
        status = "NO OBVIOUS WARNING SIGNS";
    }

    return {
        valid: true,
        status,
        score,
        hostname,
        protocol: url.protocol,
        findings:
            findings.length > 0
                ? findings
                : ["No obvious warning signs detected"],
        disclaimer:
            "Heuristic results only. This is not proof that a URL is safe or malicious.",
    };
}

// Decode URL-encoded text safely.
function decodeSafely(value) {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

module.exports = validateURL;
