import os
import shutil
import kagglehub
import pandas as pd
import numpy as np
import re
from time import time
from urllib.parse import urlparse
import tldextract
import joblib

import matplotlib.pyplot as plt
import seaborn as sns

from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.base import BaseEstimator, TransformerMixin

# ==============================
# Enhanced URL Feature Extractor
# ==============================
class EnhancedURLFeatureExtractor(BaseEstimator, TransformerMixin):
    """Extract various features from URLs"""

    def fit(self, x, y=None):
        return self

    def transform(self, urls):
        # Initialize DataFrame to store features
        features = pd.DataFrame()

        # Extract domain information for all URLs
        domains = [tldextract.extract(url) for url in urls]

        # Basic features
        features['url_length'] = [len(url) for url in urls]
        features['domain_length'] = [len(domain.domain) for domain in domains]
        features['dots_count'] = [url.count('.') for url in urls]
        features['special_char_count'] = [len(re.findall(r'[^a-zA-Z0-9.]', url)) for url in urls]
        features['digits_count'] = [len(re.findall(r'\d', url)) for url in urls]

        # URL structure analysis
        features['has_ip'] = [
            1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', urlparse(url).netloc) else 0
            for url in urls
        ]
        features['suspicious_tld'] = [
            1 if domain.suffix in ['xyz', 'top', 'ml', 'ga', 'cf', 'tk', 'gq', 'info'] else 0
            for domain in domains
        ]
        features['has_https'] = [1 if url.startswith('https://') else 0 for url in urls]
        features['domain_has_hyphen'] = [1 if '-' in domain.domain else 0 for domain in domains]
        features['subdomain_count'] = [
            len(domain.subdomain.split('.')) if domain.subdomain else 0
            for domain in domains
        ]
        features['path_length'] = [len(urlparse(url).path) for url in urls]

        # Sensitive words detection
        sensitive_words = ['bank', 'account', 'secure', 'update', 'verify', 'confirm']
        features['has_sensitive_word'] = [
            1 if any(word in url.lower() for word in sensitive_words) else 0
            for url in urls
        ]

        # Login-related words
        login_words = ['login', 'signin', 'logon', 'session']
        features['has_login_word'] = [
            1 if any(word in url.lower() for word in login_words) else 0
            for url in urls
        ]

        # Trusted domains detection
        trusted_domains = [
            'github.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com','instagram.com','flipkart.com',
            'facebook.com', 'twitter.com', 'linkedin.com', 'yahoo.com', 'paypal.com','youtube.com','snapchat.com'
        ]
        features['is_trusted_domain'] = [
            1 if any(f"{domain.domain}.{domain.suffix}".endswith(td) for td in trusted_domains) else 0
            for domain in domains
        ]
        features['is_legitimate_login'] = [
            1 if (
                any(word in url.lower() for word in login_words)
                and any(f"{domain.domain}.{domain.suffix}".endswith(td) for td in trusted_domains)
            ) else 0
            for url, domain in zip(urls, domains)
        ]
        # GitHub-specific features
        features['is_github'] = [1 if "github.com" in url.lower() else 0 for url in urls]
        features['has_github_path'] = [
            1 if "github.com" in url.lower() and len(urlparse(url).path.strip('/').split('/')) >= 2 else 0
            for url in urls
        ]
        features['has_commit_hash'] = [
            1 if re.search(r'/[a-f0-9]{30,}/', url.lower()) else 0 for url in urls
        ]

        # Educational/government domain detection
        features['is_edu_domain'] = [1 if domain.suffix == 'edu' else 0 for domain in domains]
        features['is_gov_domain'] = [1 if domain.suffix in ['gov', 'mil'] else 0 for domain in domains]

        # Entropy of the URL (measure of randomness)
        from scipy.stats import entropy
        features['url_entropy'] = [
            entropy([url.count(c)/len(url) for c in set(url)]) if len(set(url)) > 1 else 0
            for url in urls
        ]

        # Ratio of digits to URL length
        features['digit_ratio'] = features['digits_count'] / features['url_length'].replace(0, 1)

        # Number of redirections (based on count of '//')
        features['redirection_count'] = [
            url.count('//') - 1 if url.count('//') > 1 else 0
            for url in urls
        ]

        # Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
        features['is_shortened'] = [
            1 if any(shortener in url.lower() for shortener in shorteners) else 0
            for url in urls
        ]

        return features.values


if __name__ == "__main__":
    # --- Step 0: Clear KaggleHub cache (optional) ---
    kagglehub_cache = os.path.expanduser("~/.cache/kagglehub")
    if os.path.exists(kagglehub_cache):
        print("Deleting entire KaggleHub cache directory:", kagglehub_cache)
        shutil.rmtree(kagglehub_cache)

    # --- Step 1: Download dataset from KaggleHub ---
    print("Downloading dataset from KaggleHub...")
    path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls", force_download=True)
    print("Path to dataset files:", path)

    # --- Step 2: Load the dataset ---
    file_name = "phishing_site_urls.csv"
    csv_file = os.path.join(path, file_name)
    print(f"Loading dataset from {csv_file}...")

    df = pd.read_csv(csv_file)
    df = df.dropna(subset=['URL'])
    print(f"Full dataset size: {len(df)} rows")

    # If needed, sample for memory or speed
    if len(df) > 200000:
        df = df.sample(n=200000, random_state=42)
        print(f"Sampled to {len(df)} rows for tractability")

    # Standardize columns
    df.columns = [col.lower() for col in df.columns]

    # Map labels
    label_map = {"bad": 1, "good": 0}
    df['label'] = df['label'].map(label_map)

    print("Class distribution in base dataset:")
    print(df['label'].value_counts())

    # --- Step 3: Augment with domain-specific examples (GitHub, login pages, etc.) ---
    print("\nPreparing domain-specific examples...")

    github_urls = [
        "https://github.com/nikhilt77/eduSync",
        "https://github.com/nikhilt77/eduSync_Backend",
        "https://github.com/tensorflow/tensorflow",
    ]
    legitimate_login_urls = [
        "https://github.com/login",
        "https://login.microsoftonline.com",
    ]
    phishing_login_urls = [
        "https://github-auth.com/login",
        "https://secure-login-apple.com",
        "https://facebook-securelogin.com",
    ]

    custom_df = pd.DataFrame({
        'url': github_urls + legitimate_login_urls,
        'label': [0] * (len(github_urls) + len(legitimate_login_urls))  # 0 = legit
    })
    phishing_df = pd.DataFrame({
        'url': phishing_login_urls,
        'label': [1] * len(phishing_login_urls)  # 1 = phishing
    })

    custom_df_oversampled = pd.DataFrame()
    for i in range(5):
        custom_df_oversampled = pd.concat([custom_df_oversampled, custom_df])
        custom_df_oversampled = pd.concat([custom_df_oversampled, phishing_df])

    df = pd.concat([df, custom_df_oversampled], ignore_index=True)
    print(f"Final dataset size: {len(df)} rows")
    print("Final class distribution:")
    print(df['label'].value_counts())

    # --- Step 4: Feature Extraction (CountVectorizer + EnhancedURLFeatureExtractor) ---
    print("\nExtracting features...")
    start_time = time()

    count_vectorizer = CountVectorizer(analyzer='char', ngram_range=(2, 3))
    X_count = count_vectorizer.fit_transform(df['url'])
    print(f"  Count vectorizer features shape: {X_count.shape}")

    feature_extractor = EnhancedURLFeatureExtractor()
    X_url = feature_extractor.fit_transform(df['url'])
    print(f"  URL features shape: {X_url.shape}")

    X_url_sparse = csr_matrix(X_url)
    X_combined = hstack([X_count, X_url_sparse])
    print(f"Combined feature matrix shape: {X_combined.shape}")
    print(f"Feature extraction completed in {time() - start_time:.2f} seconds")

    y = df['label']

    # --- Step 5: Train-test split ---
    X_train, X_test, y_train, y_test = train_test_split(
        X_combined, y, test_size=0.2, random_state=42, stratify=y
    )

    # --- Step 6: Define base estimators + meta-learner (Stacking) ---
    from sklearn.ensemble import StackingClassifier, RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    print("\nDefining base estimators for Stacking...")

    rf1 = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    rf2 = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        class_weight='balanced',
        random_state=101,
        n_jobs=-1
    )

    # Meta-learner with max_iter=11500
    meta_lr = LogisticRegression(
        max_iter=11500,
        class_weight='balanced',
        random_state=999
    )

    # Create the StackingClassifier
    stacked_model = StackingClassifier(
        estimators=[('rf1', rf1), ('rf2', rf2)],
        final_estimator=meta_lr,
        passthrough=True,  # pass original features to meta-learner
        cv=3
    )

    # --- Step 7: Train the Stacking model ---
    print("Training Stacking model with max_iter=11500 for LR...")
    start_train = time()
    stacked_model.fit(X_train, y_train)
    end_train = time()
    print(f"Stacking model trained in {end_train - start_train:.2f} seconds")

    # --- Step 8: Evaluate ---
    print("\nEvaluating Stacking model performance...")
    y_pred_stacked = stacked_model.predict(X_test)
    stacked_accuracy = accuracy_score(y_test, y_pred_stacked)

    print(f"Stacking Accuracy: {stacked_accuracy:.4f}")
    print("Classification Report:")
    print(classification_report(y_test, y_pred_stacked))

    # Confusion Matrix
    cm_stacked = confusion_matrix(y_test, y_pred_stacked)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm_stacked, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Legitimate', 'Phishing'],
                yticklabels=['Legitimate', 'Phishing'])
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Stacking Classifier Confusion Matrix')
    model_dir = "stacking_models"
    os.makedirs(model_dir, exist_ok=True)
    plt.savefig(os.path.join(model_dir, 'stacking_confusion_matrix.png'))
    plt.show()

    # --- Step 9: Test on "problematic" URLs ---
    print("\nTesting on previously problematic URLs:")
    test_urls = [
        "https://github.com/nikhilt77/eduSync",
        "https://github.com/login",
        "https://login.microsoftonline.com",
        "https://secure-login-apple.com",
        "https://facebook-securelogin.com"
    ]
    test_count = count_vectorizer.transform(test_urls)
    test_url_features = feature_extractor.transform(test_urls)
    test_url_sparse = csr_matrix(test_url_features)
    test_combined = hstack([test_count, test_url_sparse])

    test_preds = stacked_model.predict(test_combined)
    test_probs = stacked_model.predict_proba(test_combined)[:, 1]

    for i, url in enumerate(test_urls):
        label = "Phishing" if test_preds[i] == 1 else "Legitimate"
        confidence = test_probs[i] if label == "Phishing" else (1 - test_probs[i])
        print(f"URL: {url}")
        print(f"  Prediction: {label}")
        print(f"  Confidence: {confidence*100:.2f}%\n")

    # --- Step 10: Save the stacking model ---
    print("\nSaving Stacking model...")
    joblib.dump(stacked_model, os.path.join(model_dir, 'stacked_model.pkl'))
    joblib.dump(count_vectorizer, os.path.join(model_dir, 'stacking_vectorizer.pkl'))
    joblib.dump(feature_extractor, os.path.join(model_dir, 'stacking_extractor.pkl'))

    print(f"Stacking model and vectorizer saved in {model_dir} directory.")
