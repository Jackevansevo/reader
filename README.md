# feedreader

[demo.webm](https://github.com/Jackevansevo/feedreader/assets/4996338/bf5c1b24-2a35-4885-b5f2-d18eab2500c4)


# Running locally

Preferable inside a virtualenv, install the deps:

    pip install pip-tools

    pip-sync requirements.txt

Feedreader expects to find the following environment variables in your env:

    export FLASK_SECRET_KEY=<SECRET>
    export ADMIN_PASSWORD=<SECRET>

Start the app with:

    flask run

Or:

   gunicorn app:app

# Deploying with fly.io

    fly launch

    fly secrets set FLASK_SECRET_KEY=<SECRET>
    fly secrets set ADMIN_PASSWORD=<SECRET>

    fly deploy
