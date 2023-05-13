import os

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# data processing
import numpy as np
import pandas as pd 
import csv

# API
import requests
import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

# libraries needed for feature extraction
import requests
import re
import datetime
import joblib 
import socket
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from datetime import datetime, timedelta
from requests.exceptions import ConnectionError
from urllib.parse import urlparse, ParseResult

# For the joblib
import sklearn

# For data storing
from google.cloud import storage

# pylint: disable=C0103
app = Flask(__name__)
CORS(app)

csv_file_path = 'PhishStorm_Clean_V2.csv'
df = pd.read_csv(csv_file_path)

# Initialize the GCS client
storage_client = storage.Client()

def save_url_to_csv(bucket_name, file_name, url):
    bucket = storage_client.get_bucket(bucket_name)
    blob = bucket.blob(file_name)

    if not blob.exists():
        with open('temp.csv', 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['url'])
            csvwriter.writerow([url])
        blob.upload_from_filename('temp.csv', content_type='text/csv')
    else:
        content = blob.download_as_text()
        with open('temp.csv', 'w', newline='') as csvfile:
            csvfile.write(content)
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow([url])
        blob.upload_from_filename('temp.csv', content_type='text/csv')

def retraining():
    phishtension = pd.read_csv("PhishTension_B.csv",low_memory=False)
    urls_df =  pd.read_csv("urls.csv",low_memory=False)
    features_list = []
    for url in urls_df['url']:
        y_pred = rf.predict([features])
        url_data = {'url': url,
                'Has IP':features[0],'Has @':features[1],'Has .':features[2],
                'Has -':features[3],'Url Redirections':features[4],'HTTPS':features[5],
                'Email Submission':features[6],'Url Shortening':features[7],'Length':features[8],
                'Sensitive Words':features[9],'Unicode':features[10],'Anchor':features[11],
                'DNS Record':features[12],'Google Index':features[13],'Age':features[14],
                'label':y_pred[0]}
        features_list.append(url_data)

    curated_df = pd.DataFrame(features_list)

    #drop the url columns as it is not needed
    curated_df = curated_df.drop('url', axis=1)
    phishtension = phishtension.drop('url', axis=1)

    #phishtension dataframe
    X_train = phishtension.drop('label', axis=1) 
    y_train = phishtension['label']

    X_new = curated_df.drop('label', axis=1) 
    y_new = curated_df['label']

    #y_train has dtype: int64 while y_new has dtype: object so convert it to the same data type
    y_new = y_new.astype('int64')

    # Combine the initial training data with the new data and predicted target values
    X_combined = np.concatenate((X_train, X_new))
    y_combined = np.concatenate((y_train, y_new))

    # Retrain the entire model on the combined data
    rf.fit(X_combined, y_combined)

    #Save the best model using joblib.dump()
    joblib.dump(rf, 'Phishtension_Random_Forest_Classifier.joblib')

def feature_extraction(url):
        features = []
    # 1.) Presence of IP address in URL
        ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.search(url):
            features.append(1)
        else:
            features.append(0)
            
    # 2.)  Presence of @ symbol in URL
        if '@' in url:
            features.append(1)
        else:
            features.append(0)
        
    # 3.)  3 or more dots in Hostname
        if url.count('.') > 3:
            features.append(1)
        else:
            features.append(0)
        
    # 4.)  Domain name includes (-) symbol
        if '-' in url:
            features.append(1)
        else:
            features.append(0)
        
    # 5.)  The position of the last occurrence of "//" in the URL is greater than 7
        if url.rfind('//') > 7:
            features.append(1)
        else:
            features.append(0)
        
    # 6.)  Uses / doesn't use https and issuer is not trusted
        domain = urlparse(url).netloc
        if 'https' in domain:
            features.append(1)
        else:
            features.append(0)
        
    # 7.)  Using "mail()" or "mailto:" function to submit user information
        if 'mail()' in url or 'mailto:' in url:
            features.append(1)
        else:
            features.append(0)
        
    # 8.)  TinyURL is used
        shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                        r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                        r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                        r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                        r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                        r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                        r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                        r"tr\.im|link\.zip\.net"
        
        match=re.search(shortening_services,url)
        if match:
            features.append(1)
        else:
            features.append(0)
        
    # 9.)  URL length >= 54
        if len(url) >= 54:
            features.append(1)
        else:
            features.append(0)
        
    # 10.) URL contains sensitive words
        sensitive_words = ['confirm', 'account', 'banking', 'secure', 'ebyisapi', 'webscr', 'signin', 'mail', 'install', 'toolbar', 'backup', 'paypal', 'password', 'username']
        sensitive_count = 0
        for word in sensitive_words:
            if word in url.lower():
                sensitive_count += 1
        if sensitive_count > 0:
            features.append(1)
        else:
            features.append(0)
        
    # 11.) Unicode characters can be found within the URL
        if re.search(r'[\u0080-\uffff]', url) is not None:
            features.append(1)
        else:
            features.append(0)
        
    # 12.) % of URL composed of anchor >= 31%
        if "#" in url:
            url_len = len(url)
            anchor_len = len(url.split("#")[-1])
            anchor_percent = anchor_len / url_len * 100
            if anchor_percent >= 31:
                features.append(1)
            else:
                features.append(0)
        else:
            features.append(0)

    # 13.) No DNS record for the domain
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            socket.gethostbyname(domain)
            features.append(0)
        except socket.gaierror as e:
            if e.errno == socket.EAI_NONAME:
                features.append(1)
            else:
                # handle other socket errors
                features.append(1)            
                pass

    # 14.) Webpage is not indexed by Google
        try:
            search_results = requests.get('https://www.google.com/search?q=' + url)
            if 'did not match any documents' in search_results.text:
                features.append(1)
            else:
                features.append(0)
        except:
            features.append(1)

    # 15.) Age
        try:
            domain_name = whois.whois(url)
            creation_date = domain_name.creation_date
            expiration_date = domain_name.expiration_date

            if creation_date is None:
                features.append(1)
            elif (isinstance(creation_date, str) or isinstance(expiration_date, str)):
                try:
                    creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
                except:
                    features.append(1)
            elif ((expiration_date is None) or (creation_date is None)):
                features.append(1)
            elif ((type(expiration_date) is list) or (type(creation_date) is list)):
                features.append(1)
            else:
                age_of_domain = (datetime.now() - creation_date).days
                if (age_of_domain/30) < 6:
                    features.append(1)
                else:
                    features.append(0)
        except whois.parser.PywhoisError:
            features.append(1)
            
        return features

@app.route("/")
def start():
    num_rows = len(df)
    print("Number of rows in CSV file:", num_rows)
    return "Number of rows in CSV file: " + str(num_rows)

@app.route('/check_csv', methods=['POST'])
def check_csv():
    url = request.form.get('urlWithoutProtocol')
    inside_status = url in df['domain'].values
    return jsonify({"is_inside": inside_status})

@app.route('/analyze_urlv2', methods=['POST'])
def analyze_urlv2():
    url = request.form.get('url')
    http = "http://"
    https = "https://"

    if url.startswith(http):
        domain = url.replace(http,"")
    elif url.startswith(https):
        domain = url.replace(https,"")
    else:
        domain=url

    if domain in df['domain'].values:
        result = df.loc[df['domain'] == domain, 'label'].iloc[0] #the result is string type
        if result == '1':
            result = 'Blacklisted Phishing'
        else:
            result = 'Whitelisted Clean'
        return jsonify({"report": result})
    #2. VIRUSTOTAL
    else:
        with virustotal_python.Virustotal("4235f9832d17590fb4a55d4d62d5ee38f1c2d17528ee49f9ea805261b2f13b56") as vtotal:
            try:
                url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
                report = vtotal.request(f"urls/{url_id}")
                result = report.data['attributes']['last_analysis_results']['Phishtank']['result']
                return jsonify({"report": result})
            except virustotal_python.VirustotalError as err:
                if err.response.status_code == 404:
                    try:
                        domain = urlparse(url).netloc
                        url_id = urlsafe_b64encode(domain.encode()).decode().strip("=")
                        report = vtotal.request(f"urls/{url_id}")
                        result = report.data['attributes']['last_analysis_results']['Phishtank']['result']
                        return jsonify({"report": result})
                    except:
                        return jsonify({"report": "URL is non-existent"})
                else:
                    return {"report": err}

@app.route('/features', methods=['POST'])
def features():
    url = request.form.get('url')
    
    features = feature_extraction(url)

    return jsonify({'ftrs' : features})

@app.route('/ml', methods=['POST'])
def ml():
    url = request.form.get('url')
    features = feature_extraction(url)

    try:
        clf = joblib.load('Phishtension_Random_Forest_Classifier.joblib')
        y_pred = clf.predict([features])
        output = y_pred.astype(int)
        if output == '1':
            output = 'phishing'
        else:
            output = 'clean'
        return jsonify({'rfc' : output})
    except Exception as e:
    # log the error and return an error message
        return jsonify({'rfc': str(e)})
    
@app.route('/add', methods=['POST'])
def add():
    url = request.form.get('url')
    # Replace these with your own GCS bucket name and desired file name
    bucket_name = 'retrainphishtension'
    file_name = 'urls.csv'
    
    save_url_to_csv(bucket_name, file_name, url)
    
    return jsonify({'retrain': 'yahoo'})

if __name__ == '__main__':
    server_port = os.environ.get('PORT', '8080')
    app.run(debug=True, port=server_port, host='0.0.0.0')