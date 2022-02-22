from django.shortcuts import render_to_response
from django.db.models import Count
from datetime import date, timedelta

from account.models import Member 
from content.models import *
from video.models import Video

import os
def showActivityReport(request):
    #alx: It is ugly, but I see no cleaner way to get daily counts! 
    # new users this week (7 days) information 
    new_users = []
    for x in range(7):
        day = date.today() - timedelta(7-x)
        daytotal = Member.objects.filter(
                              date_joined__range=[day,day+timedelta(1)]
                             ).aggregate(Count('date_joined'))
        new_users.append((day,daytotal['date_joined__count']))
    
    # new videos submited  this week (7 days) information
    new_videos = []
    for x in range(7):
        day = date.today() - timedelta(7-x)
        daytotal = Video.objects.filter(
                              created__range=[day,day+timedelta(1)]
                             ).aggregate(Count('created'))
        new_videos.append((day,daytotal['created__count']))
    
    # new unique sessions this week (7 days) information (from Google Analytics) 
    new_sessions = []
    #Api call to google analitics 
    new_sessions = get_new_sessions_from_ga(date.today() - timedelta(7-x),date.today())
    
    #calculate storage used
    storage_dir = '/tmp/'  #enter here the full path of the video storage directory
    storage_total = 0
    files_total = 0
    try:
        storage_total = sum( [ os.path.getsize(storage_dir+file) for file in os.listdir(storage_dir) if os.path.isfile(storage_dir+file)])
        files_total =  len(os.listdir(storage_dir))      
    except: 
        print "unexpected error accesing filesystem"

    
    #Todo: gather statistics (dummy for now)
    error_reports   = {'a':'one','b':'two','c':'three'}
    bandwidth_usage = 300
    return render_to_response("statistic/activity_report.html",{"new_users":new_users,
                                                                 "new_videos":new_videos,
                                                                 "storage_dir":storage_dir,
                                                                 "storage_total":storage_total,
                                                                 "files_total":files_total,
                                                                 "new_sessions":new_sessions }
                              )

#TBD: To be replaced by actual Google Analytics call
def get_new_sessions_from_ga(begin,end):
    dummy = []
    for x in range(7):
        day = date.today() - timedelta(7-x)
        dummy.append((day,x))
        
    return dummy
