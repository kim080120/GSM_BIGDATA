from flask import Flask, render_template_string, request
import joblib
import numpy as np
import tldextract
import urllib.parse
import math
from collections import Counter

app = Flask(__name__)
model = joblib.load('xgb_model.pkl')

# Feature Engineering 함수
SPECIAL_CHARS = "!@#$%^&*()_+-="
FILTER_WORDS = ["login", "secure", "update", "account", "bank", "confirm", "signin", "submit", "webscr", "ebayisapi", "cmd"]

def count_special_char(url):
    return sum(1 for c in url if c in SPECIAL_CHARS)

def num_port_cal(url):
    if "://" not in url:
        url = "http://" + url
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.port:
        return int(parsed_url.port)
    return 443 if parsed_url.scheme == "https" else 80

def is_ip(url):
    try:
        host = urllib.parse.urlparse(url if "://" in url else "http://"+url).hostname
        parts = host.split('.')
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts) and len(parts) == 4
    except:
        return False

def ratio_alpha_numeric(url):
    alnum = sum(c.isalnum() for c in url)
    return alnum / len(url) if len(url) > 0 else 0

def count_url_dots(url):
    return url.count('.')

def value_entropy_url(url):
    prob = [n_x/len(url) for x,n_x in Counter(url).items()]
    return -sum([p*math.log2(p) for p in prob])

def count_file_path(url):
    return url.count('/')

def is_filter(url):
    return int(any(word in url.lower() for word in FILTER_WORDS))

def feature_from_url(url):
    ext = tldextract.extract(url, include_psl_private_domains=True)
    features = {
        'len_url': len(url),
        'len_sub_domain': len(ext.subdomain),
        'len_root_domain': len(ext.domain),
        'len_suffix': len(ext.suffix),
        'is_private': int(ext.is_private),
        'count_special_char': count_special_char(url),
        'num_port': num_port_cal(url),
        'len_query': len(urllib.parse.urlparse(url if "://" in url else "http://"+url).query),
        'count_sub_domain': ext.subdomain.count('.')+1 if ext.subdomain else 0,
        'is_filter': is_filter(url),
        'ratio_alpha_numeric': ratio_alpha_numeric(url),
        'count_url_dots': count_url_dots(url),
        'value_entropy_url': value_entropy_url(url),
        'count_file_path': count_file_path(url)
    }
    return features

HTML = '''
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>악성 URL 판단 사이트</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { background: #f9fafb; font-family: 'Pretendard', 'Noto Sans KR', sans-serif; margin: 0; }
        .container { max-width: 400px; margin: 60px auto; background: #fff; border-radius: 18px; box-shadow: 0 4px 24px rgba(0,0,0,0.07); padding: 36px 28px; }
        h1 { color: #222; font-size: 2rem; margin-bottom: 18px; text-align: center; letter-spacing: -1px; }
        form { display: flex; flex-direction: column; gap: 16px; }
        input[type=url] { padding: 14px; border: 1.5px solid #e5e7eb; border-radius: 10px; font-size: 1rem; transition: border 0.2s; }
        input[type=url]:focus { border: 1.5px solid #3182f6; outline: none; }
        button { background: #3182f6; color: #fff; border: none; border-radius: 10px; padding: 14px; font-size: 1.1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #2563eb; }
        .result { margin-top: 24px; text-align: center; font-size: 1.2rem; font-weight: 600; }
        .normal { color: #10b981; }
        .malicious { color: #ef4444; }
        .footer { margin-top: 32px; text-align: center; color: #aaa; font-size: 0.95rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>악성 URL 판단 사이트</h1>
        <form method="post" action="/">
            <input type="url" name="url" placeholder="URL을 입력하세요" required autocomplete="off">
            <button type="submit">판단하기</button>
        </form>
        {% if result is not none %}
        <div class="result {{'malicious' if result else 'normal'}}">
            {% if result %}⚠️ 악성 URL로 판단됩니다!{% else %}✅ 정상 URL로 판단됩니다!{% endif %}
        </div>
        {% endif %}
    </div>
    <div class="footer">Copyright © 악성 URL 판단 사이트</div>
</body>
</html>
'''

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form.get('url', '')
        try:
            features = feature_from_url(url)
            X = np.array([list(features.values())])
            pred = model.predict(X)[0]
            result = bool(pred)
        except Exception as e:
            result = None
    return render_template_string(HTML, result=result)

if __name__ == '__main__':
    app.run(debug=True, port=5000) 