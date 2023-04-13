import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import pandas as pd
import re
from urllib.parse import urlparse
from googlesearch import search
from urllib.parse import urlparse
from tld import get_tld
import os.path
from tld import get_tld
import socket
import whois

app = Flask(__name__)
model = pickle.load(open('model.pkl', 'rb'))
Rmodel = pickle.load(open('Rmodel.pkl', 'rb'))
Lmodel = pickle.load(open('Lmodel.pkl', 'rb'))
Xmodel = pickle.load(open('Xmodel.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict',methods=['POST'])
def predict():
    '''
    For rendering results on HTML GUI
    '''

    url = request.form.get("url")
    site = search(url, 5)

    '''
    # Get the whois record for the URL
    w = whois.whois(url)

    if isinstance(w.creation_date, list):
        # If the creation date is a list, take the first element
        creation_date = w.creation_date[0]
    else:
        # If the creation date is not a list, use it as is
        creation_date = w.creation_date

    # Format the creation date as a string in a specific format
    formatted_date = creation_date.strftime("%Y-%m-%d")


    # Get the whois record for the URL
    y = whois.whois(url)
    # Get the IP address from the domain name
    ip = socket.gethostbyname(y.domain_name[0])'''


    def get_values(df,url):
        
        #Use of IP or not in domain
        def having_ip_address(url):
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
            if match:
                # print match.group()
                return 1
            else:
                # print 'No matching pattern found'
                return 0
        df['use_of_ip'] = [having_ip_address(url)]
        #print(having_ip_address(url))
        

        def abnormal_url(url):
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                # print match.group()
                return 1
            else:
                # print 'No matching pattern found'
                return 0


        df['abnormal_url'] = abnormal_url(url)

        #pip install googlesearch-python

        

        def google_index(url):
            site = search(url, 5)
            return 1 if site else 0
        df['google_index'] =  google_index(url)
    #     print(google_index(url))

        def count_dot(url):
            count_dot = url.count('.')
            return count_dot

        df['count.'] =  count_dot(url)

        def count_www(url):
            url.count('www')
            return url.count('www')

        df['count-www'] = count_www(url)

        def count_atrate(url):

            return url.count('@')

        df['count@'] =count_atrate(url)


        def no_of_dir(url):
            urldir = urlparse(url).path
            return urldir.count('/')

        df['count_dir'] =  no_of_dir(url)

        def no_of_embed(url):
            urldir = urlparse(url).path
            return urldir.count('//')

        df['count_embed_domian'] = no_of_embed(url)


        def shortening_service(url):
            match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                            'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                            'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                            'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                            'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                            'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                            'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                            'tr\.im|link\.zip\.net',
                            url)
            if match:
                return 1
            else:
                return 0

        df['short_url'] = shortening_service(url)

        def count_https(url):
            return url.count('https')

        df['count-https'] =  count_https(url)

        def count_http(url):
            return url.count('http')

        df['count-http'] = count_http(url)

        def count_per(url):
            return url.count('%')

        df['count%'] = count_per(url)

        def count_ques(url):
            return url.count('?')

        df['count?'] =  count_ques(url)

        def count_hyphen(url):
            return url.count('-')

        df['count-'] =count_hyphen(url)

        def count_equal(url):
            return url.count('=')

        df['count='] = count_equal(url)

        def url_length(url):
            return len(str(url))


        #Length of URL
        df['url_length'] = url_length(url)
        #Hostname Length

        def hostname_length(url):
            return len(urlparse(url).netloc)

        df['hostname_length'] =  hostname_length(url)

        df.head()

        def suspicious_words(url):
            match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                            url)
            if match:
                return 1
            else:
                return 0
        df['sus_url'] = suspicious_words(url)


        def digit_count(url):
            digits = 0
            for i in url:
                if i.isnumeric():
                    digits = digits + 1
            return digits


        df['count-digits']= digit_count(url)


        def letter_count(url):
            letters = 0
            for i in url:
                if i.isalpha():
                    letters = letters + 1
            return letters

        df['count-letters']=  letter_count(url)

        # pip install tld

        

        #First Directory Length
        def fd_length(url):
            urlpath= urlparse(url).path
            try:
                return len(urlpath.split('/')[1])
            except:
                return 0

        df['fd_length'] =  fd_length(url)
        from tld import get_tld
        #Length of Top Level Domain
        df['tld'] = get_tld(url,fail_silently=True)


        def tld_length(tld):
            try:
                return len(tld)
            except:
                return -1

        df['tld_length'] =  tld_length(df['tld'])
        return df
    
    df1=pd.DataFrame()
    df1=get_values(df1,url)
    df1=df1[['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@',
        'count_dir', 'count_embed_domian', 'short_url', 'count-https',
        'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length',
        'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count-digits',
        'count-letters']]

    malicious={0:'safe',1.0:'defacement',2.0:'phishing',3.0:'malware'}
    prediction=malicious[model.predict(df1)[0]]
    prediction1=malicious[Rmodel.predict(df1)[0]]
    prediction2=malicious[Lmodel.predict(df1)[0]]
    prediction3=malicious[Xmodel.predict(df1)[0]]


    return render_template('index.html', prediction_text='THE PROVIDED URL IS  {}'.format(prediction),sus='Suspicious words(1-yes/0-no) {}'.format(df1['sus_url'][0])
                           ,Rpredict='RandomForest Model Prediction - {}'.format(prediction1),Lpredict='LightGBM Model Prediction - {}'.format(prediction2),Xpredict='XGBoost Model Prediction - {}'.format(prediction3))

# @app.route('/predict_api',methods=['POST'])
# def predict_api():
#     '''
#     For direct API calls trought request
#     '''
#     data = request.get_json(force=True)
#     prediction = model.predict([np.array(list(data.values()))])

#     output = prediction[0]
#     return jsonify(output)

if __name__ == "__main__":
    app.run(debug=True)