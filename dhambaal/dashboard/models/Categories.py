from datetime import datetime
from dhambaal import db


class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    create_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'Category ({self.name}, {self.description})'

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


# CREATE TABLE 'posts' (id int PrimaryKey, title varchar(120), description Text)
# insert into posts(title,description,source)values("post title","d")
# Select * from posts

# Model view Controller - MVC
# Laravel - PHP
# Symfony - php
# ASP.NET MVC - C#
# Ruby On rails - Ruby
# phoenix - Elixir
# M -> C --> V
# Model view Template
# Django
