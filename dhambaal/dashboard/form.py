from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, SelectField, RadioField

from wtforms.validators import DataRequired, Length
from dhambaal.dashboard.models.Categories import Category


class PostForm(FlaskForm):
    title = StringField('Title', validators=[
                        DataRequired(), Length(min=3, max=50)])
    description = TextAreaField("Description", validators=[
                                DataRequired(), Length(min=3, max=1500)])
    category = SelectField('Category', choices=[
                           category.name for category in Category.query.all()])
    published = RadioField('Publish?', choices=[(
        'yes', 'Yes'), ('no', 'No')], default='yes')
    source = StringField('Source', validators=[
        DataRequired(), Length(min=3, max=20)])
    submit = SubmitField('Create')


class CatgoryForm(FlaskForm):
    name = StringField('Title', validators=[
        DataRequired(), Length(min=3, max=20)])
    description = TextAreaField("Description", validators=[
                                DataRequired(), Length(min=3, max=1500)])
    submit = SubmitField('Create')