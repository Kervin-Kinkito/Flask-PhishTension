from django.shortcuts import render
import os
import requests

url = "facebook.com"
atSymbol = 0

def homepage(request):
    service = os.environ.get('K_SERVICE', 'Unknown service')
    revision = os.environ.get('K_REVISION', 'Unknown revision')
    
    return render(request, 'homepage.html', context={
        "message": "It's running!",
        "Service": service,
        "Revision": revision,
    })

def aboutpage(request):
    return render(request, 'aboutpage.html', context={})

def featureExtraction(url):
    if '@' in url:
        atSymbol == 1
    else:
        atSymbol == 0

    return(atSymbol)