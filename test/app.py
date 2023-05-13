import os

from flask import Flask, render_template
import numpy as np
# import pandas as pd 
# import requests
# import re
# import datetime
# import joblib
# import socket
# from urllib.parse import urlparse
# from bs4 import BeautifulSoup
# import whois
# import urllib
# import urllib.request
# from datetime import datetime

# pylint: disable=C0103
app = Flask(__name__)


@app.route('/')
def start():
    """Get Cloud Run environment variables."""
    service = os.environ.get('K_SERVICE', 'Unknown service')
    revision = os.environ.get('K_REVISION', 'Unknown revision')

    url = "facebook.com"
        
# 2.)  Presence of @ symbol in URL
    if '@' in url:
        f2 = 1
    else:
        f2 = 0
    
    
    return render_template('index.html',
        Service=service,
        url=url,
        f2=f2,
        Revision=revision)

if __name__ == '__main__':
    server_port = os.environ.get('PORT', '8080')
    app.run(debug=True, port=server_port, host='0.0.0.0')
