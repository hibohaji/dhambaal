from flask import Blueprint, render_template
from dhambaal.dashboard.models.Post import Post
site = Blueprint("site", __name__, url_prefix="/")


@site.route("/")
def index():
    posts = Post.query.all()
    return render_template("index.html", posts=posts)