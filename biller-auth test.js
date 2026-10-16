/*
 * ZAP Standalone Script (JavaScript / GraalVM engine)
 * STEP 2: Authorization check — replay every endpoint from the Sites tree
 *         with Cookie + Authorization headers stripped, and compare the
 *         response status code against the original (authenticated) baseline
 *         already stored in ZAP's History.
 *
 * Script type: Stand Alone
 *
 * Logic:
 *   Send each endpoint with Cookie/Authorization stripped and report the
 *   response status code only. Only endpoints included in an in-scope
 *   ZAP Context are tested (SiteNode.isIncludedInScope()).
 *   FLAG if status is 2xx (request succeeded with no auth material).
 *   OK   if status is 401/403 (enforced, expected).
 *   REVIEW for anything else (500, redirect, etc — check manually).
 *
 * References (verified 2026-09-02):
 * - HttpMessage.cloneAll(): https://github.com/zaproxy/community-scripts/blob/main/httpsender/README.md
 * - HttpHeader.setHeader(name, null) removes header:
 *   https://javadoc.io/static/org.zaproxy/zap/2.8.0/org/parosproxy/paros/network/HttpHeader.html
 * - HttpSender ctor + sendAndReceive: https://groups.google.com/g/zaproxy-develop/c/_RZtqweBSws
 * - SiteNode walk / isLeaf / getHistoryReference:
 *   https://github.com/zaproxy/zap-core-help-id_ID/wiki/HelpUiDialogsBeanshell
 * - SiteNode.isIncludedInScope() (scope check used by ZAP's own active scan controller):
 *   http://useof.org/java-open-source/org.zaproxy.zap.model.StructuralNode
 */

// ---- CONFIG --------------------------------------------------------------
// Request headers to strip before replaying each request. Cookie and
// Authorization are the defaults; add any custom auth headers your app uses
// (e.g. "X-Api-Key", "X-Auth-Token", "Api-Key"). Case-insensitive.
var STRIP_HEADERS = ["Cookie", "Authorization"];

// Case-insensitive substrings that mark an auth rejection *in the body*, so a
// "200 OK" carrying {"error":"unauthorized"} is treated as enforced, not a
// FLAG. Tune to your app's error vocabulary.
var AUTH_ERROR_MARKERS = [
    "unauthorized", "unauthenticated", "forbidden", "access denied",
    "not authorized", "permission denied", "invalid token",
    "token expired", "login required", "authentication required",
    "please log in", "please login", "session expired"
];
// --------------------------------------------------------------------------

var Model       = Java.type("org.parosproxy.paros.model.Model");
var HttpSender  = Java.type("org.parosproxy.paros.network.HttpSender");
var Control     = Java.type("org.parosproxy.paros.control.Control");
var ExtensionHistory = Java.type("org.parosproxy.paros.extension.history.ExtensionHistory");
var HistoryReference = Java.type("org.parosproxy.paros.model.HistoryReference");
var Thread       = Java.type("java.lang.Thread");

// Pause (milliseconds) between each replayed request so the target isn't
// hammered. Set to 0 to disable.
var THROTTLE_MS = 150;

// Graceful stop: when you stop/close the script, ZAP interrupts its thread.
// We watch for that and bail out cleanly, printing whatever we have so far.
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

// initiator 6 = MANUAL_REQUEST_INITIATOR
var httpSender = new HttpSender(
    Model.getSingleton().getOptionsParam().getConnectionParam(),
    false,
    6
);
// Belt and braces: make sure the cookie jar / global HTTP state cannot
// silently re-inject the session cookie after we strip the Cookie header.
// These setters exist on modern ZAP (2.x) but not on older builds, so guard
// each one: the ctor arg (useGlobalState=false) is the real safeguard and
// these are an extra layer that must not abort the script if absent.
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
// only replay each method+url once.
var seenEndpoints = {};

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
        print("  " + pad(String(r.status), 5) + pad(r.method, 7) + r.url);
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

// Does a response body look like an auth rejection, regardless of status?
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

function testNoAuth(node, path) {
    var href = node.getHistoryReference();
    if (href === null || !node.isLeaf()) return;
    if (!node.isIncludedInScope()) return; // skip nodes not in an in-scope Context

    var method = "-";
    var url = "-";

    try {
        var baseMsg = href.getHttpMessage();
        method = baseMsg.getRequestHeader().getMethod();
        url = baseMsg.getRequestHeader().getURI().toString();

        var dedupKey = method + " " + url;
        if (seenEndpoints[dedupKey]) return; // already replayed this endpoint
        seenEndpoints[dedupKey] = true;

        // authenticated baseline captured by ZAP when the request was first seen
        var baseStatus = baseMsg.getResponseHeader().getStatusCode();
        var baseLen = baseMsg.getResponseBody().length();

        // clone the original request so method/body/other headers stay intact
        var testMsg = baseMsg.cloneAll();
        for (var h = 0; h < STRIP_HEADERS.length; h++) {
            testMsg.getRequestHeader().setHeader(STRIP_HEADERS[h], null);
        }

        // do NOT follow redirects: a 302 -> login followed to a 200 would
        // otherwise be mis-read as a successful unauthenticated request.
        httpSender.sendAndReceive(testMsg, false);
        throttle(THROTTLE_MS);
        if (extHistory !== null) {
            try {
                extHistory.addHistory(testMsg, HistoryReference.TYPE_ZAP_USER);
            } catch (histErr) {
                // non-fatal, keep going
            }
        }
        var testStatus = testMsg.getResponseHeader().getStatusCode();
        var testLen = testMsg.getResponseBody().length();
        var testBody = testMsg.getResponseBody().toString();
        var baseBody = baseMsg.getResponseBody().toString();

        // A 2xx that carries an auth-error message in the body is still a
        // rejection, so count it as enforced rather than flagging it.
        var bodyRejects = bodyHasAuthError(testBody);
        var is2xx = testStatus >= 200 && testStatus < 300;
        var enforced = (testStatus === 401 || testStatus === 403) || (is2xx && bodyRejects);
        var flagged = !enforced && is2xx;

        // Did the no-auth response reproduce the authenticated baseline?
        // Same 2xx status AND matching body content is the strongest signal
        // that the endpoint served real data with no auth material.
        var baseWas2xx = baseStatus >= 200 && baseStatus < 300;
        var lenClose = baseLen > 0 &&
            Math.abs(testLen - baseLen) <= Math.max(16, baseLen * 0.05);
        var matchesBaseline = flagged && baseWas2xx && bodiesSimilar(testBody, baseBody, lenClose);

        var tag = flagged ? "FLAG" : (enforced ? "OK" : "REVIEW");
        var verdict;
        if (flagged) {
            verdict = matchesBaseline
                ? "no-auth response matches authenticated baseline (status+body) - likely missing authz check"
                : (baseWas2xx
                    ? "no-auth request succeeded but body differs from baseline - check manually"
                    : "no-auth request succeeded; baseline was " + baseStatus + " - check manually");
        } else if (enforced) {
            verdict = (testStatus === 401 || testStatus === 403)
                ? "rejected as expected"
                : "2xx but body signals an auth error - treated as rejected";
        } else {
            verdict = "unexpected status (baseline " + baseStatus + "), check manually";
        }

        results.push({
            tag: tag, path: path, method: method, url: url,
            status: testStatus, baseStatus: baseStatus,
            testLen: testLen, baseLen: baseLen,
            matchesBaseline: matchesBaseline, verdict: verdict
        });
    } catch (e) {
        // Print immediately too, so failures are visible even if the
        // console output pane later gets scrolled/truncated.
        print("[ERROR] " + method + " " + url + "  [" + path + "]  :: " + e);
        results.push({
            tag: "ERROR", path: path, method: method, url: url,
            status: "-", baseStatus: "-", testLen: "-", baseLen: "-",
            matchesBaseline: false, verdict: String(e)
        });
    }
}

function walk(node, path) {
    var childCount = node.getChildCount();
    for (var i = 0; i < childCount; i++) {
        if (checkStop()) return; // user stopped the script -> unwind
        var child = node.getChildAt(i);
        var newPath = path + " / " + child.getNodeName();
        testNoAuth(child, newPath);
        if (checkStop()) return;
        walk(child, newPath);
    }
}

print("");
print(LINE);
print(" AUTHORIZATION CHECK - requests replayed without: " + STRIP_HEADERS.join(", "));
print(LINE);
walk(root, "");

if (aborted) {
    print("");
    print("*** STOPPED by user - partial results below (" + results.length + " endpoint(s) completed) ***");
}

var counts = { FLAG: 0, REVIEW: 0, OK: 0, ERROR: 0 };
results.forEach(function (r) { counts[r.tag] = (counts[r.tag] || 0) + 1; });

print("");
print(LINE);
print(" RESULTS   " + results.length + " endpoint(s) tested");
print("   " + MARK.FLAG + " " + counts.FLAG + " flagged     " +
      MARK.REVIEW + " " + counts.REVIEW + " review     " +
      MARK.OK + " " + counts.OK + " ok     " +
      MARK.ERROR + " " + counts.ERROR + " error");
print(LINE);

// Most important first; empty groups are skipped automatically.
printGroup("FLAG",   "FLAGGED - no-auth request returned data (investigate first)");
printGroup("REVIEW", "REVIEW - unexpected response, check manually");
printGroup("ERROR",  "ERROR - request failed");
printGroup("OK",     "OK - rejected as expected");
print("");

var ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
ScriptVars.setGlobalCustomVar("authz.results", JSON.stringify(results));