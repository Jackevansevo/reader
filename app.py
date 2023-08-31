import os
import io
import bleach
from urllib.parse import parse_qs, quote_plus, urlencode, urlparse
from pygments import highlight
from pygments.lexers import guess_lexer
from pygments.formatters import HtmlFormatter

import listparser
import requests
from bs4 import BeautifulSoup
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
    g,
    send_file,
)
from flask_httpauth import HTTPBasicAuth
from reader import make_reader, Reader
from reader.exceptions import FeedExistsError
from werkzeug.security import check_password_hash, generate_password_hash
import humanize
from tasks import update_feeds
from flask_htmx import HTMX

app = Flask(__name__)
htmx = HTMX(app)

app.config.from_prefixed_env()

app.jinja_env.filters["quote_plus"] = lambda u: quote_plus(u)
app.jinja_env.filters["naturaltime"] = lambda u: naturaltime(u)
app.jinja_env.filters["urlparse"] = lambda u: urlparse(u)

auth = HTTPBasicAuth()

users = {"admin": generate_password_hash(os.environ.get("ADMIN_PASSWORD"))}

EXTRA_TAGS = {
    "cite",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "image",
    "img",
    "link",
    "p",
    "pre",
    "quote",
    "s",
    "small",
    "span",
}


def naturaltime(value):
    try:
        return humanize.naturaltime(value)
    except ValueError:
        pass


def get_reader() -> Reader:
    if "reader" not in g:
        g.reader = make_reader("db.sqlite")

    return g.reader


@app.teardown_appcontext
def teardown_reader(exception):
    reader = g.pop("reader", None)

    if reader is not None:
        reader.close()


@app.before_request
@auth.login_required()
def authenticate():
    pass


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username


@app.get("/feed/favicon")
def get_favicon():
    reader = get_reader()
    feed = reader.get_feed(request.args["url"])

    if feed is None:
        return Response(status=404)

    allowed_content_types = (
        "image/jpeg",
        "image/x-icon",
        "image/png",
        "image/vnd.microsoft.icon",
        "image/svg+xml",
    )

    target = feed.link or feed.url

    parsed_url = urlparse(target)
    root_url = parsed_url._replace(path="").geturl()

    if feed.link == feed.url:
        target = root_url

    # Try to find the favicon in the document
    try:
        resp = requests.get(target)
    except requests.exceptions.InvalidURL:
        pass
    else:
        if resp.ok and "text/html" in resp.headers["Content-Type"]:
            for link in BeautifulSoup(resp.content, "html.parser").find_all(
                "link", rel="icon"
            ):
                target = link["href"]
                scheme = urlparse(target).scheme
                if scheme == "":
                    target = parsed_url._replace(path=target).geturl()
                elif scheme == "data":
                    continue

                resp = requests.get(target)
                if resp.ok and resp.headers["Content-Type"] in allowed_content_types:
                    return Response(
                        resp.content,
                        content_type=resp.headers["Content-Type"],
                        headers={"Cache-Control": "max-age=604800"},
                    )

    # Legacy browser style
    try:
        resp = requests.get(os.path.join(root_url, "favicon.ico"))
    except requests.exceptions.InvalidURL:
        pass
    else:
        if resp.ok and resp.headers["Content-Type"] in allowed_content_types:
            return Response(
                resp.content,
                content_type=resp.headers["Content-Type"],
                headers={"Cache-Control": "max-age=604800"},
            )

    return Response(status=200, headers={"Cache-Control": "max-age=604800"})


@app.route("/add", methods=["GET", "POST"])
def add_feed():
    if request.method == "GET":
        return render_template("feed_add.html")
    elif request.method == "POST":
        reader = get_reader()
        url = request.form["url"]
        try:
            reader.add_feed(url)
        except FeedExistsError as ex:
            flash(str(ex), "warn")
            return redirect("/add")

        reader.update_feeds()

        feed = reader.get_feed(url)
        flash(f'Added feed: "{feed.title or feed.link or feed.url}"', "ok")

        return redirect(url_for("feed", url=url))


@app.get("/feed")
def feed():
    reader = get_reader()
    feed = reader.get_feed(request.args["url"])
    if htmx:
        show = request.args.get("show")
        if show is None or show == "unread":
            entries = list(reader.get_entries(feed=request.args["url"], read=False))
        else:
            entries = list(reader.get_entries(feed=request.args["url"]))
        return render_template("feed_partial.html", entries=entries, feed=feed)
    else:
        return render_template("feed.html", feed=feed)


@app.get("/feeds")
def feeds():
    reader = get_reader()
    feeds = reader.get_feeds()
    if htmx:
        return render_template("feeds_partial.html", feeds=list(feeds))
    else:
        return render_template("feeds.html", feeds=list(feeds))


@app.get("/entry")
def entry():
    reader = get_reader()
    url, entry_id = request.args["url"], request.args["id"]
    reader.mark_entry_as_read((url, entry_id))
    entry = reader.get_entry((url, entry_id))

    content = entry.content
    if not entry.content and entry.summary:
        content = entry.summary
    else:
        content = entry.content[0].value

    content = bleach.clean(
        content,
        tags=bleach.sanitizer.ALLOWED_TAGS | EXTRA_TAGS,
        strip=True,
        attributes=bleach.sanitizer.ALLOWED_ATTRIBUTES | {"img": ["src"]},
    )

    soup = BeautifulSoup(content, "html.parser")

    # Attempt to highlight any code blocks with pygments
    for code_section in soup.find_all("code"):
        text = code_section.text
        if len(text.split()) == 1:
            continue
        code_section.replace_with(
            BeautifulSoup(
                highlight(text, guess_lexer(text), HtmlFormatter()), "html.parser"
            )
        )

    if htmx:
        return render_template(
            "entry_partial.html",
            entry=entry,
            content=str(soup),
        )
    else:
        return render_template(
            "entry.html",
            entry=entry,
            content=str(soup),
        )


@app.post("/entry")
def mark_read():
    reader = get_reader()
    entry = reader.get_entry((request.args["url"], request.args["id"]))
    read = bool(int(request.args["read"]))
    reader.set_entry_read(entry, read)
    return redirect(
        url_for("entry")
        + "?"
        + urlencode({"url": request.args["url"], "id": request.args["id"]})
    )


@app.get("/delete_feed")
def confirm_delete_feed():
    reader = get_reader()
    feed = reader.get_feed(request.args["url"])
    return render_template("feed_confirm_delete.html", feed=feed)


@app.post("/delete_feed")
def delete_feed():
    reader = get_reader()
    feed_url = request.args["url"]
    reader.delete_feed(feed_url)
    flash(f'Feed: "{feed_url}" deleted', "bad")
    return redirect("/")


@app.post("/refresh_feeds")
def refresh_feeds():
    referer = request.headers["Referer"]
    update_feeds.delay()
    flash("Updating feeds in background", "ok")
    return redirect(referer)


@app.post("/refresh_feed")
def refresh_feed():
    reader = get_reader()
    referer = request.headers["Referer"]
    feed_url = request.args["url"]
    try:
        reader.update_feed(feed_url)
    except reader.exceptions.ParseError as ex:
        flash(str(ex), "bad")
    return redirect(referer)


@app.post("/mark_all_read")
def mark_all_read():
    reader = get_reader()
    referer = request.headers["Referer"]
    parsed_url = urlparse(referer)
    if parsed_url.path == "/feed":
        feed_url, *_ = parse_qs(parsed_url.query)["url"]
        entries = reader.get_entries(feed=feed_url, read=False)
    else:
        entries = reader.get_entries(read=False)

    for entry in entries:
        reader.mark_entry_as_read(entry)

    return redirect(referer)


@app.route("/import", methods=["GET", "POST"])
def import_feeds():
    if request.method == "GET":
        return render_template("import.html")
    else:
        parsed = listparser.parse(request.files["opml"].read())
        feeds = parsed["feeds"]
        reader = get_reader()
        for feed in feeds:
            reader.add_feed(feed["url"], exist_ok=True)
        reader.update_feeds(workers=10)
        flash(f"{len(feeds)} Feeds imported successfully", "ok")
        return redirect("/feeds")


@app.get("/export")
def export_feeds():
    reader = get_reader()
    feeds = reader.get_feeds()
    contents = render_template("export.xml", feeds=list(feeds))
    return send_file(
        io.BytesIO(contents.encode()), download_name="feeds.opml", as_attachment=True
    )


@app.get("/db.sqlite")
def export_db():
    return send_file("db.sqlite")


@app.route("/upload/db.sqlite", methods=["GET", "POST"])
def import_db():
    if request.method == "GET":
        return render_template("upload_db.html")
    elif request.method == "POST":
        db = request.files["db"]
        db.save("db.sqlite")
        flash(f'Imported DB "{db.filename}"', "ok")
        return redirect(url_for("feeds"))


@app.route("/")
def index():
    reader = get_reader()
    feeds = reader.get_feeds()
    url = request.args.get("url")
    entry_id = request.args.get("id")
    starting_after = (
        (url, entry_id) if url is not None and entry_id is not None else None
    )
    entries = reader.get_entries(read=False, limit=100, starting_after=starting_after)
    if htmx:
        return render_template(
            "index_partial.html", feeds=list(feeds), entries=list(entries)
        )
    else:
        return render_template("index.html", feeds=list(feeds), entries=list(entries))
