د ننګرهار پوهنتون آنلاین کتابتون - Backend
==========================================

دا Backend د FastAPI او SQLite په وسیله جوړ شوی او د کتابتون V2 Frontend سره برابر دی.

فایلونه:
- main.py              د API او سرور اصلي کوډ
- requirements.txt     اړین Python کتابتونونه
- data/                د SQLite ډیټابېس د ساتلو فولډر
- uploads/             د PDF فایلونو د ساتلو فولډر

د Windows نصب:
1) د backend فولډر په CMD کې خلاص کړئ.
2) دا کمانډونه په ترتیب اجرا کړئ:

   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt

3) د مدیر حساب لپاره د سرور له پیل مخکې دا متغیرونه وټاکئ:

   set ADMIN_USERNAME=libraryadmin
   set ADMIN_PASSWORD=خپل_قوي_پټ_نوم
   set SESSION_SECRET=یو_اوږد_تصادفي_راز

4) سرور چالان کړئ:

   uvicorn main:app --reload

5) API او سرور:
   http://127.0.0.1:8000
   http://127.0.0.1:8000/docs
   http://127.0.0.1:8000/health

د Render لپاره:
- Build Command:
  pip install -r requirements.txt
- Start Command:
  uvicorn main:app --host 0.0.0.0 --port $PORT
- Environment Variables:
  ADMIN_USERNAME
  ADMIN_PASSWORD
  SESSION_SECRET
  COOKIE_SECURE=true
  DATA_DIR=/var/data

په Render کې Persistent Disk په /var/data مسیر کې ونښلوئ، څو ډیټابېس او PDF فایلونه د سرور له بیا پیل وروسته هم پاتې شي.

د Backend مهم امکانات:
- د کارن حساب جوړول او ننوتل
- د کارن د پټ نوم PBKDF2 hashing
- د Admin او User رولونه
- د PDF فایل اپلوډ او د PDF signature تایید
- د 50MB فایل محدودیت
- د کتابونو د مدیر تایید او رد
- د کتابونو لټون، کتګوري او pagination
- Favorites او My Uploads
- د ډاونلوډ شمېر
- د کتابونو، کارنانو او ډاونلوډونو احصایې

مهم:
- د دې Backend API د V2 Frontend سره برابر شوی.
- که Frontend په بل Domain یا Port کې کوربه کوئ، باید CORS او د API base URL تنظیم شي.
- د عامه رسمي استعمال مخکې HTTPS، rate limiting، د ایمیل تایید، malware scanning، منظم backup او امنیتي ارزونه ضروري دي.
- د ADMIN_PASSWORD او SESSION_SECRET لپاره قوي او ځانګړي ارزښتونه وکاروئ.
- په دې پروژه کې هېڅ فایل په نقطه (.) نه پیلېږي.
