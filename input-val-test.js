/*
 * ZAP Standalone Script (JavaScript / GraalVM engine)
 * STEP 3: Input validation probing — for each endpoint with a JSON body,
 *         mutate one field at a time (negative / huge / missing / wrong
 *         data type) and print the raw response body for manual review.
 *         No automated pass/fail — verdict is up to you.
 *
 * Script type: Stand Alone
 *
 * Scope of mutation (per field, based on its captured type):
 *   number  -> negative value, huge value (1e19), field removed, string value
 *   string  -> field removed, number value
 *   other types (bool/array/object/null) -> field removed only
 *
 * Endpoints tested are pulled from the Sites tree and filtered to only
 * those included in an in-scope ZAP Context (SiteNode.isIncludedInScope()) —
 * add your target host(s) to a Context and mark it in-scope first, or no
 * endpoints will be tested.
 *
 * Only top-level JSON body fields are mutated (no nested object recursion)
 * to keep output readable — extend recurseFields() if you need nested.
 *
 * Authentication:
 *   Set AUTH_HEADER_VALUE below to the full Authorization header value
 *   (e.g. "Bearer eyJ..."). It's applied to every mutated test request,
 *   overwriting whatever Authorization header was originally captured.
 *
 * References (verified 2026-09-02):
 * - HttpMessage.cloneAll(): https://github.com/zaproxy/community-scripts/blob/main/httpsender/README.md
 * - HttpHeader content-length handling / setRequestBody:
 *   https://javadoc.io/static/org.zaproxy/zap/2.8.0/org/parosproxy/paros/network/HttpHeader.html
 * - HttpSender ctor + sendAndReceive: https://groups.google.com/g/zaproxy-develop/c/_RZtqweBSws
 * - SiteNode walk / isLeaf / getHistoryReference:
 *   https://github.com/zaproxy/zap-core-help-id_ID/wiki/HelpUiDialogsBeanshell
 * - SiteNode.isIncludedInScope() (scope check used by ZAP's own active scan controller):
 *   http://useof.org/java-open-source/org.zaproxy.zap.model.StructuralNode
 */

var Model      = Java.type("org.parosproxy.paros.model.Model");
var HttpSender = Java.type("org.parosproxy.paros.network.HttpSender");
var Control    = Java.type("org.parosproxy.paros.control.Control");
var ExtensionHistory  = Java.type("org.parosproxy.paros.extension.history.ExtensionHistory");
var HistoryReference  = Java.type("org.parosproxy.paros.model.HistoryReference");

var Thread     = Java.type("java.lang.Thread");

// Graceful stop: when you stop/close the script, ZAP interrupts its thread.
// We watch for that and unwind cleanly instead of dying mid-request.
var aborted = false;
function checkStop() {
    if (!aborted && Thread.currentThread().isInterrupted()) {
        aborted = true;
    }
    return aborted;
}

// initiator 6 = MANUAL_REQUEST_INITIATOR
var httpSender = new HttpSender(
    Model.getSingleton().getOptionsParam().getConnectionParam(),
    false,
    6
);
// Don't let the global cookie jar / HTTP state attach extra credentials:
// test requests should carry only the Authorization header we set below.
// These setters exist on modern ZAP (2.x) but not older builds, so guard
// each one; the ctor arg (useGlobalState=false) is the real safeguard.
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

// Used to register each sent test message in ZAP's History tab / Sites tree
// (HttpSender.sendAndReceive alone does NOT persist to History).
// Ref: https://github.com/zaproxy/zaproxy/blob/main/zap/src/main/java/org/zaproxy/zap/authentication/AuthenticationHelper.java
//      https://github.com/zaproxy/zap-extensions/blob/main/addOns/automation/src/main/java/org/zaproxy/addon/automation/jobs/SpiderJob.java
var extHistory = Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);

var siteTree = Model.getSingleton().getSession().getSiteTree();
var root = siteTree.getRoot();

// Dedup: the Sites tree can hold several nodes for the same endpoint;
// only probe each method+url once.
var seenEndpoints = {};

var MAX_BODY_PRINT = 2000; // truncate very long responses in the console

// Pause (milliseconds) between each mutated request, so the target isn't
// hammered. Set to 0 to disable.
var THROTTLE_MS = 150;

// ---- CONFIG -------------------------------------------------------------
// Only test these field names (case-sensitive). Leave empty [] to test
// every top-level field in each endpoint's body.
var FIELDS_TO_TEST = [
    // "amount",
    // "otp",
    // "email"
];

// ---- AUTH CONFIG ------------------------------------------------------
// Paste the full Authorization header value to use for every test request.
// Example: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
var AUTH_HEADER_VALUE = "Bearer 12e1e256d4515809643c78dc93de76ec11a392f878fee3c4e102755dfb4428e4";
// -------------------------------------------------------------------

// ---- display helpers -----------------------------------------------------
var LINE = "========================================================================";
var THIN = "------------------------------------------------------------------------";
var testCount = 0;
var tally = {
    "ACCEPTED (2xx)": 0, "REDIRECT (3xx)": 0, "REJECTED (4xx)": 0,
    "SERVER ERROR (5xx)": 0, "OTHER": 0, "SCRIPT ERROR": 0
};
function classify(status) {
    if (status >= 200 && status < 300) return "ACCEPTED (2xx)";
    if (status >= 300 && status < 400) return "REDIRECT (3xx)";
    if (status >= 400 && status < 500) return "REJECTED (4xx)";
    if (status >= 500)                 return "SERVER ERROR (5xx)";
    return "OTHER";
}
// For a validation probe: 2xx (malformed input accepted) is the suspicious
// one, 4xx (rejected) is the healthy one, 5xx (crash) is worth a look.
function markerFor(cls) {
    if (cls.indexOf("2xx") !== -1) return "[!]";
    if (cls.indexOf("4xx") !== -1) return "[+]";
    if (cls.indexOf("5xx") !== -1 || cls.indexOf("ERROR") !== -1) return "[x]";
    return "[?]";
}
function indent(text) {
    return String(text).split("\n").map(function (ln) { return "      " + ln; }).join("\n");
}

function buildMutations(key, value) {
    var muts = [];
    var t = typeof value;

    if (t === "number") {
        muts.push({ label: "negative value", apply: function (o) { o[key] = -Math.abs(value) - 1; } });
        muts.push({ label: "extremely huge value (1e19)", apply: function (o) { o[key] = 1e19; } });
        muts.push({ label: "missing field", apply: function (o) { delete o[key]; } });
        muts.push({ label: "wrong type (string instead of number)", apply: function (o) { o[key] = "abc123"; } });
    } else if (t === "string") {
        muts.push({ label: "missing field", apply: function (o) { delete o[key]; } });
        muts.push({ label: "wrong type (number instead of string)", apply: function (o) { o[key] = 999999; } });
    } else {
        // boolean / array / object / null — just test removal
        muts.push({ label: "missing field", apply: function (o) { delete o[key]; } });
    }
    return muts;
}

function sendMutated(baseMsg, method, url, path, key, mutation) {
    try {
        var bodyText = baseMsg.getRequestBody().toString();
        var bodyObj = JSON.parse(bodyText);

        mutation.apply(bodyObj);
        var newBody = JSON.stringify(bodyObj);

        var testMsg = baseMsg.cloneAll();
        testMsg.setRequestBody(newBody);
        testMsg.getRequestHeader().setContentLength(testMsg.getRequestBody().length());

        if (AUTH_HEADER_VALUE) {
            testMsg.getRequestHeader().setHeader("Authorization", AUTH_HEADER_VALUE);
        }

        // Do NOT follow redirects: a validation failure that responds with a
        // 3xx -> error/login page would otherwise be reported as that target's
        // status/body instead of the real rejection.
        httpSender.sendAndReceive(testMsg, false);

        if (THROTTLE_MS > 0) {
            try { Thread.sleep(THROTTLE_MS); }
            catch (ignore) { aborted = true; } // InterruptedException => stop requested
        }

        // Register the sent request/response in History so it shows up in
        // the History tab / Sites tree, same as a manual "Resend".
        if (extHistory !== null) {
            try {
                extHistory.addHistory(testMsg, HistoryReference.TYPE_ZAP_USER);
            } catch (histErr) {
                print("WARN: could not add to History: " + histErr);
            }
        }

        var status = testMsg.getResponseHeader().getStatusCode();
        var reqBody = testMsg.getRequestBody().toString();
        var respBody = testMsg.getResponseBody().toString();
        if (respBody.length > MAX_BODY_PRINT) {
            respBody = respBody.substring(0, MAX_BODY_PRINT) + "\n...[truncated, " + respBody.length + " chars total]";
        }

        testCount++;
        var cls = classify(status);
        tally[cls] = (tally[cls] || 0) + 1;

        print("");
        print(THIN);
        print(markerFor(cls) + " #" + testCount + "  " + cls + "  (HTTP " + status + ")");
        print("    " + method + " " + url);
        print("    field '" + key + "'  ->  " + mutation.label);
        print("    [request body]");
        print(indent(reqBody.length ? reqBody : "(empty body)"));
        print("    [response body]");
        print(indent(respBody.length ? respBody : "(empty body)"));
    } catch (e) {
        testCount++;
        tally["SCRIPT ERROR"] = (tally["SCRIPT ERROR"] || 0) + 1;

        print("");
        print(THIN);
        print("[x] #" + testCount + "  SCRIPT ERROR");
        print("    " + method + " " + url);
        print("    field '" + key + "'  ->  " + mutation.label);
        print("    " + e);
    }
}

function testEndpoint(node, path) {
    var href = node.getHistoryReference();
    if (href === null || !node.isLeaf()) return;
    if (!node.isIncludedInScope()) return; // skip nodes not in an in-scope Context

    try {
        var baseMsg = href.getHttpMessage();
        var method = baseMsg.getRequestHeader().getMethod();
        var url = baseMsg.getRequestHeader().getURI().toString();

        var dedupKey = method + " " + url;
        if (seenEndpoints[dedupKey]) return; // already probed this endpoint
        seenEndpoints[dedupKey] = true;

        var contentType = baseMsg.getRequestHeader().getHeader("Content-Type");
        var bodyText = baseMsg.getRequestBody().toString();

        if (!bodyText || bodyText.length === 0) {
            return; // nothing to mutate (e.g. GET with no body)
        }
        if (!contentType || contentType.indexOf("json") === -1) {
            print("[-] SKIP (non-JSON body, extend script for this content-type): " + method + " " + url + " [" + path + "]");
            return;
        }

        var bodyObj;
        try {
            bodyObj = JSON.parse(bodyText);
        } catch (e) {
            print("[-] SKIP (body not valid JSON): " + method + " " + url + " [" + path + "]");
            return;
        }

        var fieldsToProcess = FIELDS_TO_TEST.length > 0
            ? Object.keys(bodyObj).filter(function (k) { return FIELDS_TO_TEST.indexOf(k) !== -1; })
            : Object.keys(bodyObj);

        if (fieldsToProcess.length === 0) {
            print("[-] SKIP (no matching fields from FIELDS_TO_TEST in this body): " + method + " " + url + " [" + path + "]");
            return;
        }

        fieldsToProcess.forEach(function (key) {
            if (checkStop()) return; // remaining fields become no-ops once stopped
            var mutations = buildMutations(key, bodyObj[key]);
            mutations.forEach(function (mutation) {
                if (checkStop()) return;
                sendMutated(baseMsg, method, url, path, key, mutation);
            });
        });
    } catch (e) {
        print("WARN: error processing '" + path + "': " + e);
    }
}

function walk(node, path) {
    var childCount = node.getChildCount();
    for (var i = 0; i < childCount; i++) {
        if (checkStop()) return; // user stopped the script -> unwind
        var child = node.getChildAt(i);
        var newPath = path + " / " + child.getNodeName();
        testEndpoint(child, newPath);
        if (checkStop()) return;
        walk(child, newPath);
    }
}

print("");
print(LINE);
print(" INPUT VALIDATION PROBE - negative / huge / missing / wrong-type mutations");
print(LINE);
print(" Markers:  [!] 2xx accepted (suspicious)   [+] 4xx rejected (healthy)");
print("           [x] 5xx server error            [?] other / redirect");
walk(root, "");

print("");
print(LINE);
if (aborted) {
    print(" STOPPED by user - tally below is partial.");
} else {
    print(" DONE.");
}
print(" " + testCount + " mutation(s) sent across " +
      Object.keys(seenEndpoints).length + " endpoint(s)");
print(THIN);
[
    "ACCEPTED (2xx)", "REJECTED (4xx)", "SERVER ERROR (5xx)",
    "REDIRECT (3xx)", "OTHER", "SCRIPT ERROR"
].forEach(function (k) {
    print("   " + markerFor(k) + " " + pad(k, 20) + tally[k]);
});
print(THIN);
print(" Review the [!] (2xx) and [x] (5xx) cases above first.");
print(LINE);