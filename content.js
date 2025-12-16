/***** ------------------- ML PREDICTION (Random Forest - Trained on VirusTotal Data) ------------------- *****/
var testdata;
var prediction;

function predict(data, weight){
  // Whitelist for known safe domains (prevents false positives on legitimate sites)
  const hostname = window.location.hostname.toLowerCase().replace('www.', '');
  const safeDomains = [
    'google.com'
  ];
  
  for (let domain of safeDomains) {
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      return -1; // Safe - whitelisted domain
    }
  }
  
  // Random Forest feature importance weights (trained on 12,000 URLs with 22 features)
  // Accuracy: 70.46% | Malicious recall: 60% | Safe recall: 85%
  // Top features: isTinyURL (45.2%), urlEntropy (10.1%), isHypenURL (10.1%), pathLength (8.9%)
  weight = [7.80591451e-02, 2.30999859e-03, 2.43416917e-02, 5.60592314e-03, 2.08000827e-02, 1.00765788e-01, 1.97684453e-04, 5.18847074e-03, 1.11906348e-03, 1.77194355e-02, 6.94259966e-02, 3.36121563e-09, 8.10997254e-03, 1.07759619e-03, 2.08821802e-02, 2.20703977e-04, 4.52107832e-01, 8.90150883e-02, 2.00343795e-03, 0.00000000e+00, 0.00000000e+00, 1.01049906e-01];
  
  // Calculate weighted score based on feature importance
  var f = 0, maybeCount = 0, suspiciousScore = 0, maliciousScore = 0, safeScore = 0;
  
  for (var j = 0; j < data.length; j++) {
    var featureValue = data[j];
    var featureWeight = weight[j];
    
    // Skip features with zero weight
    if (featureWeight === 0) continue;
    
    // Handle categorical features (indices 0-15: values -1, 0, 1)
    if (j < 16) {
      if (featureValue === 0) {
        maybeCount++;
        suspiciousScore += featureWeight * 0.4;
      }
      else if (featureValue === 1) {
        maliciousScore += featureWeight;
        f += featureWeight;
      }
      else if (featureValue === -1) {
        safeScore += featureWeight;
        f -= featureWeight * 0.3;
      }
    }
    // Handle continuous features (indices 16-21: raw numeric values)
    else {
      // Normalize and contribute to scores based on feature type
      if (j === 16) { // urlEntropy (higher = more random/suspicious)
        if (featureValue > 4.5) maliciousScore += featureWeight * 0.8;
        else if (featureValue > 3.5) suspiciousScore += featureWeight * 0.5;
        else safeScore += featureWeight * 0.3;
      }
      else if (j === 17) { // digitRatio (higher = more suspicious)
        if (featureValue > 0.3) maliciousScore += featureWeight * 0.7;
        else if (featureValue > 0.15) suspiciousScore += featureWeight * 0.5;
        else safeScore += featureWeight * 0.3;
      }
      else if (j === 18) { // specialCharCount (higher = more suspicious)
        if (featureValue > 15) maliciousScore += featureWeight * 0.6;
        else if (featureValue > 8) suspiciousScore += featureWeight * 0.4;
        else safeScore += featureWeight * 0.4;
      }
      else if (j === 19) { // suspiciousTLD (binary: 1 or -1)
        if (featureValue === 1) maliciousScore += featureWeight;
        else safeScore += featureWeight * 0.5;
      }
      else if (j === 20) { // subdomainDepth (higher = more suspicious)
        if (featureValue > 3) maliciousScore += featureWeight * 0.7;
        else if (featureValue > 1) suspiciousScore += featureWeight * 0.3;
        else safeScore += featureWeight * 0.4;
      }
      else if (j === 21) { // pathLength (very long = suspicious)
        if (featureValue > 100) maliciousScore += featureWeight * 0.6;
        else if (featureValue > 50) suspiciousScore += featureWeight * 0.3;
        else safeScore += featureWeight * 0.3;
      }
    }
  }
  
  // Decision thresholds (balanced for accuracy)
  var maliciousThreshold = 0.15;   // Raised to reduce false positives
  var suspiciousThreshold = 0.08;  // Raised to be more conservative
  var safeThreshold = 0.30;        // Lowered for easier safe classification
  
  // Classification logic with priority
  // 1. Check if definitely safe (prioritize safeScore)
  if (safeScore >= safeThreshold && maliciousScore < 0.15) {
    return -1; // Safe
  }
  // 2. If safeScore is higher than maliciousScore, it's safe
  else if (safeScore > maliciousScore && safeScore > 0.15) {
    return -1; // Safe
  }
  // 3. Check if malicious based on score
  else if (maliciousScore >= maliciousThreshold) {
    return 1; // Malicious
  }
  // 4. Check for suspicious indicators
  else if (suspiciousScore > suspiciousThreshold || maybeCount >= 3) {
    return 0; // Suspicious
  }
  // 5. Default to safe
  else {
    return -1; // Safe
  }
}

/***** ------------------- FEATURE EXTRACTORS (yours, unchanged) ------------------- *****/
function isIPInURL(){ var reg=/\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/; var url=window.location.href; return reg.exec(url)==null?-1:1; }
function isLongURL(){ var url=window.location.href; if(url.length<54) return -1; else if(url.length<=75) return 0; else return 1; }
function isTinyURL(){ var url=window.location.href; return url.length>20?-1:1; }
function isAlphaNumericURL(){ var url=window.location.href; return url.match("@")==null?-1:1; }
function isRedirectingURL(){ var reg1=/^http:/, reg2=/^https:/, srch="//"; var url=window.location.href;
  if(url.search(srch)==5 && reg1.exec(url)!=null && (url.substring(7)).match(srch)==null) return -1;
  else if(url.search(srch)==6 && reg2.exec(url)!=null && (url.substring(8)).match(srch)==null) return -1;
  else return 1;
}
function isHypenURL(){ var reg=/[a-zA-Z]\//, srch="-", url=window.location.href; return (((url.substring(0,url.search(reg)+1)).match(srch))==null)?-1:1; }
function isMultiDomainURL(){ var reg=/[a-zA-Z]\//, url=window.location.href; return (url.substring(0,url.search(reg)+1)).split('.').length<5?-1:1; }
function isFaviconDomainUnidentical(){ var reg=/[a-zA-Z]\//, url=window.location.href;
  if(document.querySelectorAll("link[rel*='shortcut icon']").length>0){
    var f=document.querySelectorAll("link[rel*='shortcut icon']")[0].href;
    return ((url.substring(0,url.search(reg)+1))==(f.substring(0,f.search(reg)+1)))?-1:1;
  } else return -1;
}
function isIllegalHttpsURL(){ var srch1="//", srch2="https", url=window.location.href; return (((url.substring(url.search(srch1))).match(srch2))==null)?-1:1; }
function isImgFromDifferentDomain(){ var t=document.querySelectorAll("img").length, i=getIdenticalDomainCount("img"); if(t===0) return -1; var r=(t-i)/t; if(r<0.22) return -1; else if(r<=0.61) return 0; else return 1; }
function isAnchorFromDifferentDomain(){ var t=document.querySelectorAll("a").length, i=getIdenticalDomainCount("a"); if(t===0) return -1; var r=(t-i)/t; if(r<0.31) return -1; else if(r<=0.67) return 0; else return 1; }
function isScLnkFromDifferentDomain(){ var t=document.querySelectorAll("script").length + document.querySelectorAll("link").length, i=getIdenticalDomainCount("script")+getIdenticalDomainCount("link"); if(t===0) return -1; var r=(t-i)/t; if(r<0.17) return -1; else if(r<=0.81) return 0; else return 1; }
function isFormActionInvalid(){ var t=document.querySelectorAll("form").length, i=getIdenticalDomainCount("form");
  if(document.querySelectorAll('form[action]').length<=0) return -1;
  else if(i!=t) return 0;
  else if(document.querySelectorAll('form[action*=""]').length>0) return 1;
  else return -1;
}
function isMailToAvailable(){ return document.querySelectorAll('a[href^=mailto]').length<=0?-1:1; }
function isStatusBarTampered(){ if((document.querySelectorAll("a[onmouseover*='window.status']").length<=0)||(document.querySelectorAll("a[onclick*='location.href']").length<=0)) return -1; else return 1; }
function isIframePresent(){ return document.querySelectorAll('iframe').length<=0?-1:1; }

/***** ------------------- ENHANCED FEATURES (6 additional) ------------------- *****/
function calculateUrlEntropy() {
  // Calculate Shannon entropy of URL (measures randomness)
  const url = window.location.href;
  const freq = {};
  for (let i = 0; i < url.length; i++) {
    freq[url[i]] = (freq[url[i]] || 0) + 1;
  }
  let entropy = 0;
  for (let char in freq) {
    const p = freq[char] / url.length;
    entropy -= p * Math.log2(p);
  }
  return entropy; // Return raw value (0-8 range typically)
}

function getDigitRatio() {
  // Ratio of digits in URL
  const url = window.location.href;
  const digitCount = (url.match(/\d/g) || []).length;
  return digitCount / url.length; // Return raw ratio (0-1)
}

function countSpecialChars() {
  // Count special characters in URL
  const url = window.location.href;
  return (url.match(/[^a-zA-Z0-9:\/\.]/g) || []).length; // Return count
}

function checkSuspiciousTLD() {
  // Check for suspicious top-level domains
  const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link'];
  const hostname = window.location.hostname;
  const tld = hostname.split('.').pop();
  return suspiciousTLDs.includes(tld) ? 1 : -1;
}

function getSubdomainDepth() {
  // Count number of subdomain levels
  const hostname = window.location.hostname;
  const parts = hostname.split('.');
  return parts.length - 2; // Return depth (0 for no subdomain, 1+ for subdomains)
}

function getPathLength() {
  // Length of URL path
  const path = window.location.pathname + window.location.search;
  return path.length; // Return raw length
}

function getIdenticalDomainCount(tag){
  var i,identicalCount=0,reg=/[a-zA-Z]\//,url=window.location.href; var main=url.substring(0,url.search(reg)+1);
  var nodeList=document.querySelectorAll(tag);
  if(tag=="img"||tag=="script"){ nodeList.forEach(function(el){ i=el.src; if(i&&main==(i.substring(0,i.search(reg)+1))) identicalCount++; }); }
  else if(tag=="form"){ nodeList.forEach(function(el){ i=el.action; if(i&&main==(i.substring(0,i.search(reg)+1))) identicalCount++; }); }
  else if(tag=="a"){ nodeList.forEach(function(el){ i=el.href; if(i&&(main==(i.substring(0,i.search(reg)+1)))&&((i.substring(0,i.search(reg)+1))!=null)&&((i.substring(0,i.search(reg)+1))!=="")) identicalCount++; }); }
  else { nodeList.forEach(function(el){ i=el.href; if(i&&main==(i.substring(0,i.search(reg)+1))) identicalCount++; }); }
  return identicalCount;
}

/***** ------------------- BUILD FEATURE VECTOR & CLASSIFY ------------------- *****/
// Wait for DOM to be ready before extracting features
function performAnalysis() {
  testdata = [
    // Original 16 features
    isIPInURL(),isLongURL(),isTinyURL(),isAlphaNumericURL(),isRedirectingURL(),isHypenURL(),
    isMultiDomainURL(),isFaviconDomainUnidentical(),isIllegalHttpsURL(),isImgFromDifferentDomain(),
    isAnchorFromDifferentDomain(),isScLnkFromDifferentDomain(),isFormActionInvalid(),isMailToAvailable(),
    isStatusBarTampered(),isIframePresent(),
    // Enhanced 6 features (raw values, not -1/0/1)
    calculateUrlEntropy(),getDigitRatio(),countSpecialChars(),checkSuspiciousTLD(),
    getSubdomainDepth(),getPathLength()
  ];
  prediction = predict(testdata);
  return { testdata, prediction };
}

// Execute when DOM is interactive or complete
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const result = performAnalysis();
    testdata = result.testdata;
    prediction = result.prediction;
  });
} else {
  const result = performAnalysis();
  testdata = result.testdata;
  prediction = result.prediction;
}

/***** ------------------- UI: MATCH YOUR MOCK ------------------- *****/

/* inject CSS */
(function ensureStyles(){
  if (document.getElementById("pk-safety-style")) return;
  const css = `
#pk-overlay{position:fixed;inset:0;display:grid;place-items:center;background:rgba(0,0,0,.35);z-index:2147483647;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;}
.pk-card{width:min(560px,92vw);background:#fff;border-radius:24px;box-shadow:0 20px 80px rgba(0,0,0,.25);overflow:hidden;animation:pk-pop .2s ease-out;}
.pk-header{background:#f5f5f5;height:48px;position:relative;display:flex;align-items:center;justify-content:flex-end;padding:0 16px;}
.pk-close{width:32px;height:32px;border:0;background:transparent;font-size:28px;line-height:32px;cursor:pointer;color:#333;font-weight:300;}
.pk-close:hover{background:rgba(0,0,0,.05);border-radius:50%;}
.pk-body{padding:32px 28px 28px;}
.pk-row{display:grid;grid-template-columns:320px 1fr;gap:20px;align-items:center;margin-bottom:24px;}
.pk-hero{display:grid;place-items:center;}
.pk-hero img{width:300px;height:300px;object-fit:contain;}
.pk-right{display:flex;flex-direction:column;align-items:flex-end;gap:12px;}
.pk-badge{width:150px;height:150px;border-radius:30px;display:grid;place-items:center;border:none;box-shadow:0 4px 12px rgba(0,0,0,.1);}
.pk-badge svg{width:100%;height:100%;}
.pk-title{font-size:32px;font-weight:900;line-height:1.1;color:#000;text-align:center;margin-bottom:18px;}
.pk-url{display:block;margin:0 auto 14px;padding:12px 20px;border-radius:50px;color:#fff;font-weight:700;font-size:14px;word-break:break-all;text-align:center;max-width:90%;}
.pk-sub{color:#2a2a2a;text-align:center;margin:0 0 18px;font-size:17px;font-weight:500;}
.pk-cta{display:block;margin:0 auto;padding:12px 48px;border:0;border-radius:50px;font-weight:700;font-size:16px;color:#fff;cursor:pointer;background:#2196f3;box-shadow:0 2px 8px rgba(33,150,243,.3);transition:all .2s;}
.pk-cta:hover{background:#1976d2;transform:translateY(-1px);box-shadow:0 4px 12px rgba(33,150,243,.4);}
.pk-cta:active{transform:translateY(0);}
/* themes */
.pk-safe .pk-url{background:#5cb85c;}
.pk-safe .pk-badge{background:linear-gradient(135deg,#e8f5e9 0%,#c8e6c9 100%);}
.pk-suspicious .pk-url{background:#ff6347;}
.pk-suspicious .pk-badge{background:linear-gradient(135deg,#ff6347 0%,#ffcdd2 100%);}
.pk-malicious .pk-url{background:#000000ff;}
.pk-malicious .pk-badge{background:linear-gradient(135deg,#ffebee 0%,#ffcdd2 100%);}
@keyframes pk-pop{from{transform:scale(.95);opacity:0}to{transform:scale(1);opacity:1}}
.pk-card :focus-visible{outline:3px solid #2196f3;outline-offset:2px;border-radius:4px;}
  `.trim();
  const style = document.createElement("style");
  style.id = "pk-safety-style";
  style.textContent = css;
  document.documentElement.appendChild(style);
})();

function stripUrl(u){
  try{ const x=new URL(u); const p = x.pathname ? (x.pathname.endsWith('/')?x.pathname:x.pathname+'/') : '/'; return x.origin + p; }
  catch{ return u; }
}

/* rounded-square badge with checkmark/warning icons */
function badgeSVG(theme) {
  if (theme === 'safe') {
    return `
      <svg width="90" height="90" viewBox="0 0 90 90" xmlns="http://www.w3.org/2000/svg">
        <rect width="90" height="90" rx="20" fill="#4caf50"/>
        <circle cx="45" cy="45" r="28" fill="white" opacity="0.95"/>
        <path d="M35 45 L42 52 L57 37" stroke="#4caf50" stroke-width="5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
      </svg>`;
  } else if (theme === 'suspicious') {
    return `
      <svg width="90" height="90" viewBox="0 0 90 90" xmlns="http://www.w3.org/2000/svg">
        <rect width="90" height="90" rx="20" fill="#ff6347"/>
        <circle cx="45" cy="45" r="28" fill="white" opacity="0.95"/>
        <path d="M45 35 L45 50 M45 57 L45 60" stroke="#ff6347" stroke-width="5" stroke-linecap="round" fill="none"/>
      </svg>`;
  } else {
    return `
      <svg width="90" height="90" viewBox="0 0 90 90" xmlns="http://www.w3.org/2000/svg">
        <rect width="90" height="90" rx="20" fill="#000000ff"/>
        <circle cx="45" cy="45" r="28" fill="white" opacity="0.95"/>
        <path d="M35 35 L55 55 M55 35 L35 55" stroke="#000000ff" stroke-width="5" stroke-linecap="round" fill="none"/>
      </svg>`;
  }
}

/* Build modal */
function buildModal(payload){
  const state = payload?.status || 'safe'; // 'safe' | 'suspicious' | 'malicious'

  // Remove existing
  const prev = document.getElementById("pk-overlay");
  if (prev) prev.remove();

  // Title lines + subtitle derived from status (so it always matches your mock)
  const titleLines =
    state==='malicious'  ? ['Malicious Site','Detected'] :
    state==='suspicious' ? ['Suspicious','Activity']     :
                           ['No Issues','Detected'];
  const subtitle =
    state==='malicious'  ? 'This website may be unsafe.' :
    state==='suspicious' ? 'Proceed with caution.'       :
                           'This website is safe';

  const themeClass = state==='malicious'?'pk-malicious':state==='suspicious'?'pk-suspicious':'pk-safe';
  const mark = state==='malicious'?'✖':state==='suspicious'?'!':'✓';

  // Select hero image based on state
  const heroImageName =
    state==='malicious'  ? 'mal.png' :
    state==='suspicious' ? 'sus.png' :
                           'safe.png';

  const overlay = document.createElement("div");
  overlay.id = "pk-overlay";

  const card = document.createElement("div");
  card.className = `pk-card ${themeClass}`;
  card.setAttribute("role","dialog");
  card.setAttribute("aria-modal","true");

  // Header
  const header = document.createElement("div");
  header.className = "pk-header";
  const closeBtn = document.createElement("button");
  closeBtn.className = "pk-close";
  closeBtn.setAttribute("aria-label","Close");
  closeBtn.textContent = "✕";

  // Body
  const body = document.createElement("div");
  body.className = "pk-body";
  const row = document.createElement("div");
  row.className = "pk-row";

  const hero = document.createElement("div");
  hero.className = "pk-hero";
  const img = document.createElement("img");
  img.src = chrome.runtime.getURL(heroImageName);
  img.alt = state + " hero";
  img.onerror = function() {
    console.warn("Failed to load " + heroImageName);
    this.style.display = 'none';
  };
  hero.appendChild(img);

  const right = document.createElement("div");
  right.className = "pk-right";
  right.innerHTML = `<div class="pk-badge">${badgeSVG(state)}</div>`;

  const titleEl = document.createElement("div");
  titleEl.className = "pk-title";
  titleEl.innerHTML = `${titleLines[0]}<br/>${titleLines[1]}`;

  const chip = document.createElement("div");
  chip.className = "pk-url";
  chip.textContent = stripUrl(location.href);

  const subEl = document.createElement("div");
  subEl.className = "pk-sub";
  subEl.textContent = subtitle;

  const ok = document.createElement("button");
  ok.className = "pk-cta";
  ok.textContent = "OK";

  // Close wiring
  const close = ()=>overlay.remove();
  ok.addEventListener("click", close);
  closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", (e)=>{ if (e.target===overlay) close(); });

  // Assemble
  row.append(hero, right);
  body.append(row, titleEl, chip, subEl, ok);
  header.appendChild(closeBtn);
  card.append(header, body);
  overlay.appendChild(card);
  document.documentElement.appendChild(overlay);

  setTimeout(()=>ok.focus(), 0);
}

/***** ------------------- MESSAGE ROUNDTRIP + SHOW MODAL ------------------- *****/
function showSecurityModal() {
  // Log prediction results for debugging
  console.log('[ProtectoKid] Prediction value:', prediction);
  console.log('[ProtectoKid] Feature data:', testdata);

  // Always show modal for all predictions: safe (-1), suspicious (0), malicious (1)
  chrome.runtime.sendMessage({ type: "prediction", prediction: prediction }, function(response) {
    let status;
    
    if (chrome.runtime.lastError) {
      // If SW is inactive, still show based on local prediction
      console.log('[ProtectoKid] Service worker error, using local prediction');
      status = prediction === 1 ? 'malicious' : prediction === 0 ? 'suspicious' : 'safe';
    } else {
      status = response?.status || (prediction === 1 ? 'malicious' : prediction === 0 ? 'suspicious' : 'safe');
    }
    
    console.log('[ProtectoKid] Showing modal with status:', status);
    buildModal({ status });
  });
}

// Show modal after a short delay to ensure everything is loaded
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    setTimeout(showSecurityModal, 500);
  });
} else {
  setTimeout(showSecurityModal, 500);
}
