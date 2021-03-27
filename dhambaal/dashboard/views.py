from flask import Blueprint, render_template, request, url_for, redirect, flash, get_flashed_messages
from dhambaal.dashboard.models.Post import Post
from dhambaal.dashboard.models.Categories import Category
from dhambaal.dashboard.form import PostForm, CatgoryForm

# Dashboard Blueprint
dashboard = Blueprint("dashboard", __name__,
                      url_prefix="/dashboard", template_folder="templates")


@dashboard.route("/")
def index():
    return render_template("dashboard.html")


@dashboard.route("/posts/")
def posts():
    posts = Post.query.all()
    return render_template("posts/posts.html", posts=posts)


@dashboard.route("/create-post/", methods=['GET', 'Post'])
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        title = form.data.get('title')
        description = form.data.get('description')
        source = form.data.get('source')
        category = form.data.get('category')
        published = form.data.get('published')
        post = Post(title=title, description=description,
                    source=source, category=category, published=published)
        post.save_to_db()
        flash("Post created successfully", 'is-success')
        return redirect(url_for('dashboard.posts'))
    return render_template("posts/create_update.html", form=form, title="Create Form")


@dashboard.route("/post/<int:id>/update", methods=['GET', 'Post'])
def update_post(id):
    post = Post.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.description = form.description.data
        post.source = form.source.data
        post.published = form.published.data
        post.category = form.category.data
        post.update()
        flash("Post updated successfully", 'is-success')
        return redirect(url_for('dashboard.posts'))
    elif request.method == 'GET':
        form.title.data = post.title
        form.description.data = post.description
        form.source.data = post.source
        form.published.data = post.published
        form.category.data = post.category
    return render_template("posts/create_update.html", form=form, title="Update Post")



@dashboard.route("/post/<int:id>/delete")
def delete_post(id):
    post = Post.query.get_or_404(id)
    if post:
        post.delete()
        flash("Post deleted successfully", "is-success")
        return redirect(url_for('dashboard.posts'))
    return render_template("posts/posts.html")


@dashboard.route("/categories/")
def categories():
    categories = Category.query.all()
    return render_template("categories/categories.html", categories=categories)


@dashboard.route("/create-category" , methods=['GET', 'Post'])
def create_category():
    form = CatgoryForm()
    if form.validate_on_submit():
        name = form.data.get('name')
        description = form.data.get('description')
        category = Category(name=name, description=description)
        category.save_to_db()
        flash("Category created successfully", 'is-success')
        return redirect(url_for('dashboard.categories'))
    return render_template("categories/create_update.html",form=form, name="Create Category")

@dashboard.route("/category/<int:id>/update", methods=['GET', 'Post'])
def update_category(id):
    category = Category.query.get_or_404(id)
    form = CatgoryForm()
    if form.validate_on_submit():
        category.name = form.name.data
        category.description = form.description.data
        category.update()
        flash("Category updated successfully", 'is-success')
        return redirect(url_for('dashboard.categories'))
    elif request.method == 'GET':
        form.name.data = category.name
        form.description.data = category.description
    return render_template("categories/create_update.html", form=form, title="Update Categories")

@dashboard.route("/category/<int:id>/delete")
def delete_category(id):
    category = Category.query.get_or_404(id)
    if category:
        category.delete()
        flash("Category deleted successfully", "is-success")
        return redirect(url_for('dashboard.categories'))
    return render_template("categories/categories.html")