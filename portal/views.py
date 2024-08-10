from django.shortcuts import render
from django.http import HttpResponse

# Create your views here.
def portal(request):
    return render(request, 'portal/portal.html')
