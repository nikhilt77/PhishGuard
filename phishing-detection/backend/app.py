from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix
import re
import os
import traceback
import tldextract
from urllib.parse import urlparse, urlunparse
from sklearn.base import BaseEstimator, TransformerMixin
import pandas as pd

app = Flask(__name__)
CORS(app)

KNOWN_DOMAINS = {
    "google.com",
    "amazon.com",
    "amazon.in",
    "instagram.com",
    "youtube.com",
}

def maybe_trim_url(original_url):
    parsed = urlparse(original_url)
    domain_info = tldextract.extract(original_url)
    short_domain = f"{domain_info.domain}.{domain_info.suffix}".lower()
    if short_domain in KNOWN_DOMAINS:
        trimmed = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '',    # clear params
            '',    # clear query
            ''     # clear fragment
        ))
        return trimmed
    else:
        return original_url

class EnhancedURLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract various features from URLs with improved domain knowledge"""

    def fit(self, x, y=None):
        return self

    def transform(self, urls):
        features = pd.DataFrame()
        domains = [tldextract.extract(url) for url in urls]

        features['url_length'] = [len(url) for url in urls]
        features['domain_length'] = [len(d.domain) for d in domains]
        features['dots_count'] = [url.count('.') for url in urls]
        features['special_char_count'] = [len(re.findall(r'[^a-zA-Z0-9.]', url)) for url in urls]
        features['digits_count'] = [len(re.findall(r'\d', url)) for url in urls]

        features['has_ip'] = [
            1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                          urlparse(url).netloc) else 0
            for url in urls
        ]
        features['suspicious_tld'] = [
            1 if d.suffix in ['xyz','top','ml','ga','cf','tk','gq','info'] else 0
            for d in domains
        ]
        features['has_https'] = [
            1 if url.startswith('https://') else 0 for url in urls
        ]
        features['domain_has_hyphen'] = [
            1 if '-' in d.domain else 0 for d in domains
        ]
        features['subdomain_count'] = [
            len(d.subdomain.split('.')) if d.subdomain else 0
            for d in domains
        ]
        features['path_length'] = [
            len(urlparse(url).path) for url in urls
        ]

        # Sensitive words
        sensitive_words = ['bank','account','secure','update','verify','confirm']
        features['has_sensitive_word'] = [
            1 if any(w in url.lower() for w in sensitive_words) else 0
            for url in urls
        ]

        # Login words
        login_words = ['login','signin','logon','session']
        features['has_login_word'] = [
            1 if any(w in url.lower() for w in login_words) else 0
            for url in urls
        ]

        # Trusted domains
        trusted_domains = [
            'github.com','google.com','microsoft.com','apple.com','amazon.com',
            'instagram.com','flipkart.com','facebook.com','twitter.com',
            'linkedin.com','yahoo.com','paypal.com','youtube.com','snapchat.com'
        ]
        features['is_trusted_domain'] = [
            1 if any(f"{d.domain}.{d.suffix}".endswith(td) for td in trusted_domains)
            else 0 for d in domains
        ]
        features['is_legitimate_login'] = [
            1 if (any(w in url.lower() for w in login_words) and
                  any(f"{d.domain}.{d.suffix}".endswith(td) for td in trusted_domains))
            else 0
            for url,d in zip(urls,domains)
        ]

        # GitHub-specific
        features['is_github'] = [
            1 if "github.com" in url.lower() else 0 for url in urls
        ]
        features['has_github_path'] = [
            1 if ("github.com" in url.lower() and
                  len(urlparse(url).path.strip('/').split('/'))>=2)
            else 0 for url in urls
        ]
        features['has_commit_hash'] = [
            1 if re.search(r'/[a-f0-9]{30,}/', url.lower()) else 0
            for url in urls
        ]

        # Edu/gov
        features['is_edu_domain'] = [
            1 if d.suffix=='edu' else 0 for d in domains
        ]
        features['is_gov_domain'] = [
            1 if d.suffix in ['gov','mil'] else 0 for d in domains
        ]

        # Additional
        from scipy.stats import entropy
        features['url_entropy'] = [
            entropy([url.count(c)/len(url) for c in set(url)]) if len(set(url))>1 else 0
            for url in urls
        ]
        features['digit_ratio'] = (
            features['digits_count'] /
            features['url_length'].replace(0,1)
        )
        features['redirection_count'] = [
            url.count('//')-1 if url.count('//')>1 else 0
            for url in urls
        ]
        shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cli.gs','ow.ly']
        features['is_shortened'] = [
            1 if any(s in url.lower() for s in shorteners) else 0
            for url in urls
        ]

        return features.values

def load_models():
    print("Loading ML models...")
    models = {}
    try:
        models['rf_model'] = joblib.load('stacking_models/stacked_model.pkl')
        models['rf_vectorizer'] = joblib.load('stacking_models/stacking_vectorizer.pkl')
        models['rf_extractor'] = joblib.load('stacking_models/stacking_extractor.pkl')
        print("✓ New Random Forest model loaded from 'stacking_models/' successfully")
    except Exception as e:
        print(f"⚠ Error loading Random Forest model: {e}")

    try:
        models['svm_coef'] = np.load('improved_models/improved_svm_coef.npy')
        models['svm_intercept'] = np.load('improved_models/improved_svm_intercept.npy')
        models['svm_vectorizer'] = joblib.load('improved_models/improved_vectorizer.pkl')
        models['svm_extractor'] = joblib.load('improved_models/improved_extractor.pkl')
        print("✓ SVM model loaded successfully (improved_models/)")
    except Exception as e:
        print(f"⚠ Error loading SVM model: {e}")

    models['rf_available'] = all(
        k in models for k in ['rf_model','rf_vectorizer','rf_extractor']
    )
    models['svm_available'] = all(
        k in models for k in [
            'svm_coef','svm_intercept','svm_vectorizer','svm_extractor'
        ]
    )
    if models['rf_available'] and models['svm_available']:
        print("✓ All models loaded successfully")
    else:
        missing = []
        if not models['rf_available']:
            missing.append("Random Forest")
        if not models['svm_available']:
            missing.append("SVM")
        print(f"⚠ Some models could not be loaded: {', '.join(missing)}")

    return models

MODELS = load_models()

app = Flask(__name__)
CORS(app)

@app.route('/health',methods=['GET'])
def health_check():
    return jsonify({
        "status":"healthy",
        "rf_available":MODELS.get('rf_available',False),
        "svm_available":MODELS.get('svm_available',False)
    })

@app.route('/predict',methods=['POST'])
def predict():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error":"No URL provided"}),400

    original_url = data['url']
    url = maybe_trim_url(original_url)

    base_rf_weight = float(data.get('rf_weight',0.6))
    base_svm_weight = float(data.get('svm_weight',0.4))
    base_threshold = float(data.get('threshold',0.5))
    use_adaptive = data.get('adaptive',True)

    try:
        if use_adaptive:
            result = adaptive_blend_predictions(
                url, base_rf_weight, base_svm_weight, base_threshold
            )
        else:
            result = standard_blend_predictions(
                url, base_rf_weight, base_svm_weight, base_threshold
            )
        return jsonify(result)
    except Exception as e:
        error_info = {
            "error": str(e),
            "traceback": traceback.format_exc(),
            "prediction":"Error",
            "probability":50
        }
        print(f"Error processing {url}: {str(e)}")
        return jsonify(error_info),500

@app.route('/check_url',methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url','')
    if not url:
        return jsonify({"error":"No URL provided"}),400
    return jsonify({
        "in_blacklist":False,
        "in_whitelist":False
    })

def predict_with_random_forest(url):
    if not MODELS.get('rf_available'):
        raise ValueError("Random Forest model not available")

    extractor = MODELS['rf_extractor']
    custom_feats = extractor.transform([url])

    vectorizer = MODELS['rf_vectorizer']
    text_feats = vectorizer.transform([url])

    combined = hstack([text_feats, csr_matrix(custom_feats)])
    print("DEBUG combined shape (RF):", combined.shape)

    rf_model = MODELS['rf_model']
    prediction = rf_model.predict(combined)[0]
    probabilities = rf_model.predict_proba(combined)[0]
    phishing_prob = probabilities[1]*100

    return {
        "prediction":"Phishing" if prediction==1 else "Legitimate",
        "probability":phishing_prob,
        "raw_probabilities":probabilities.tolist()
    }

def predict_with_svm(url):
    """
    Modified to interpret decision_value>0 => class=1 => 'Legitimate'.
    The sigmoid => legitimate probability. Then we invert if needed.
    """
    if not MODELS.get('svm_available'):
        raise ValueError("SVM model not available")

    svm_extractor = MODELS['svm_extractor']
    custom_feats = svm_extractor.transform([url])

    svm_vectorizer = MODELS['svm_vectorizer']
    text_feats = svm_vectorizer.transform([url])

    combined = hstack([text_feats, csr_matrix(custom_feats)])

    coef = MODELS['svm_coef']
    intercept = MODELS['svm_intercept']
    decision_value = (combined.dot(coef.T))[0,0] + intercept[0]

    # This probability is the 'legitimate' probability if we trained with class=1 => legitimate
    legit_prob = 1 / (1 + np.exp(-decision_value))

    # So final_legit_prob is how likely it's legitimate.
    # If decision_value>0 => SVM sees it as class=1 => legitimate
    if decision_value > 0:
        # final_legit_prob = legit_prob
        # so 'legitimate' is 100*legit_prob
        final_label = "Legitimate"
        final_legit_prob = legit_prob
    else:
        # decision_value<0 => class=0 => 'phishing'
        # so legitimate prob is 1-legit_prob
        final_label = "Phishing"
        final_legit_prob = 1-legit_prob

    # We'll return 'probability' as the legitimate probability * 100
    # so a site with 0.915 => 91.5% legitimate
    probability_legit = final_legit_prob*100

    return {
        "prediction": final_label,
        "probability": probability_legit,
        "decision_value": float(decision_value)
    }

def standard_blend_predictions(url, rf_weight=0.6, svm_weight=0.4, threshold=0.5):
    rf_res = predict_with_random_forest(url)
    svm_res = predict_with_svm(url)

    # For RF, we interpret 'probability' as phishing prob
    # For SVM, we interpret 'probability' as legitimate prob now
    # => we must invert the SVM prob if we want phishing prob
    # or we can unify them as 'phishing probability' vs. 'legit probability'.

    rf_prob_norm = rf_res["probability"]/100.0   # phishing probability from RF
    # SVM => 'probability' is legitimate => so phishing prob = 1 - (svm_res['probability']/100)
    svm_legit_norm = svm_res["probability"]/100.0
    svm_phish_norm = 1 - svm_legit_norm

    # Weighted blend of phishing probabilities
    blended_phish_prob = (rf_weight*rf_prob_norm) + (svm_weight*svm_phish_norm)

    final_label = "Phishing" if blended_phish_prob>=threshold else "Legitimate"

    return {
        "prediction": final_label,
        "probability": round(blended_phish_prob*100,2),  # phishing prob
        "rf_prediction": rf_res["prediction"],
        "rf_probability": round(rf_res["probability"],2),   # phishing prob
        "svm_prediction": svm_res["prediction"],
        # We'll also show the 'svm_probability' as the legitimate prob from SVM
        "svm_probability": round(svm_res["probability"],2), # legitimate prob
        "blend_method": "Standard weighted (RF=phish, SVM=legit)",
        "rf_weight": rf_weight,
        "svm_weight": svm_weight,
        "threshold": threshold
    }

def preprocess_url(url):
    parsed = urlparse(url)
    domain_info = tldextract.extract(url)
    return {
        "domain": domain_info.domain,
        "suffix": domain_info.suffix,
        "subdomain": domain_info.subdomain,
        "full_domain": f"{domain_info.domain}.{domain_info.suffix}",
        "has_www": domain_info.subdomain=="www",
        "path": parsed.path,
        "query": parsed.query,
        "is_github": "github" in domain_info.domain.lower(),
        "is_login_page": any(w in url.lower() for w in ['login','signin','auth','account']),
        "is_known_domain": domain_info.domain.lower() in [
            'google','microsoft','apple','amazon','facebook','github',
            'twitter','linkedin','instagram','youtube'
        ],
        "has_suspicious_tld": domain_info.suffix in ['xyz','top','ml','ga','cf','tk','gq','info'],
        "is_education": domain_info.suffix=='edu',
        "is_government": domain_info.suffix in ['gov','mil'],
        "path_length": len(parsed.path),
        "has_suspicious_chars": bool(re.search(r'[^\w\-\.]', domain_info.domain)),
        "has_digits_in_domain": bool(re.search(r'\d', domain_info.domain))
    }

def adaptive_blend_predictions(url, base_rf_weight=0.6, base_svm_weight=0.4, base_threshold=0.5):
    feats = preprocess_url(url)
    short_domain = f"{feats['domain']}.{feats['suffix']}".lower()
    # GitHub override
    if feats["is_github"] and (
        "github.com/login" in url or
        re.match(r'github\.com/[^/]+/[^/]+', url)
    ):
        return {
            "prediction":"Legitimate",
            "probability":1.0,
            "blend_method":"GitHub override",
            "note":"Recognized as GitHub pattern"
        }
    if short_domain == "google.com":
        return {
             "prediction": "Legitimate",
             "probability": 0.0,  # or 0.0 phishing probability
             "blend_method": "Domain override",
             "note": "Detected subdomain of google.com"
        }

    rf_res = predict_with_random_forest(url)
    svm_res = predict_with_svm(url)

    # RF => 'probability' is phishing
    rf_prob_norm = rf_res["probability"]/100.0
    # SVM => 'probability' is legitimate => convert to phishing
    svm_legit_norm = svm_res["probability"]/100.0
    svm_phish_norm = 1 - svm_legit_norm

    rf_w = base_rf_weight
    svm_w = base_svm_weight
    threshold = base_threshold
    blend_method = "Base"

    if feats["is_known_domain"]:
        rf_w=0.7
        svm_w=0.3
        threshold=0.55
        blend_method+=" + known_domain"

    if feats["is_login_page"]:
        threshold=0.45
        blend_method+=" + login_page"

    if feats["has_suspicious_tld"] or feats["has_suspicious_chars"]:
        threshold=min(threshold,0.4)
        blend_method+=" + suspicious_url"

    if feats["is_education"] or feats["is_government"]:
        rf_w=0.8
        svm_w=0.2
        threshold=max(threshold,0.7)
        blend_method+=" + edu/gov"

    # Confidence-based
    rf_conf = abs(rf_prob_norm-0.5)*2
    svm_conf = abs(svm_phish_norm-0.5)*2
    gap = abs(rf_conf-svm_conf)
    if gap>0.3:
        if rf_conf>svm_conf:
            boost = min(gap*0.5,0.2)
            rf_w+=boost
            svm_w-=boost
            blend_method+=" + rf_conf_boost"
        else:
            boost = min(gap*0.5,0.2)
            svm_w+=boost
            rf_w-=boost
            blend_method+=" + svm_conf_boost"

    # Agreement
    rf_verdict=(rf_prob_norm>=0.5)
    svm_verdict=(svm_phish_norm>=0.5)
    if rf_verdict==svm_verdict:
        if rf_verdict:
            threshold=max(0.45,threshold-0.05)
            blend_method+=" + agreement (phishing)"
        else:
            threshold=min(0.55,threshold+0.05)
            blend_method+=" + agreement (legitimate)"

    blended_phish_prob=(rf_w*rf_prob_norm)+(svm_w*svm_phish_norm)
    final_label="Phishing" if blended_phish_prob>=threshold else "Legitimate"

    return {
        "prediction": final_label,
        "probability": round(blended_phish_prob*100,2), # phishing prob
        "rf_prediction": rf_res["prediction"],
        "rf_probability": round(rf_res["probability"],2),  # phish prob from RF
        "svm_prediction": svm_res["prediction"],
        # 'svm_probability' here is legitimate prob from SVM
        "svm_probability": round(svm_res["probability"],2),
        "blend_method": blend_method,
        "rf_weight": round(rf_w,3),
        "svm_weight": round(svm_w,3),
        "threshold": round(threshold,2),
        "url_features": feats
    }

if __name__=='__main__':
    port=int(os.environ.get('PORT',5000))
    app.run(host='0.0.0.0',port=port,debug=True)
