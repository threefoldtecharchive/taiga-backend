# Threefold Circles #

## Setup development environment ##


#### Setup development database

###### Install Postgres
```
sudo apt install postgresql postgresql-contrib
sudo service postgresql start 
```

###### create database and proper development user
```
create database taiga;
CREATE USER taiga WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE "taiga" to taiga;
```

###### Prepare and run project
- Prepare configuration
 - `cp settings/local.example.py settings/local.py`
 - Make sure `setting/local.py` contains
  ```
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
             'NAME': 'taiga',
             'USER': 'taiga',
             'PASSWORD': 'changeme',
             'HOST': '',
             'PORT': '',
         }
  }in

  PRIVATE_KEY = "25p85axmtVLM8aGp+gYJz6y+AIAVEddb5szzwi+WsSg="
  THREEBOT_URL = "https://login.threefold.me"
  ```

Just execute these commands in your virtualenv(wrapper):
```
pip install -r requirements.txt
cp settings/local.example.py settings/local.py
python3 manage.py migrate --noinput
python3 manage.py loaddata initial_user
python3 manage.py loaddata initial_project_templates
python3 manage.py compilemessages
```

**IMPORTANT: Threefold Circles only runs with python 3.5+**

Initial auth data: admin/123123
