import uuid
from django.db import models
from ckeditor.fields import RichTextField


class Department(models.Model):
    name = models.CharField(max_length=50)
    slug = models.SlugField(unique=True)

    def __str__(self):
        return self.name


class Workshop(models.Model):
    def get_image_path(self, filename):
        ext = filename.split('.')[-1]
        filename = 'vidyut_workshop_' + "%s.%s" % (uuid.uuid4(), ext)
        return 'static/events/covers/' + filename

    name = models.CharField(max_length=150)
    slug = models.SlugField(unique=True)
    cover = models.ImageField(upload_to=get_image_path, null=True, blank=True)
    dept = models.ForeignKey(Department, on_delete=models.PROTECT, null=True, blank=True)
    description = models.CharField(max_length=200, null=True, blank=True)
    details = RichTextField(null=True, blank=True)
    fee = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.name


class Competition(models.Model):
    def get_image_path(self, filename):
        ext = filename.split('.')[-1]
        filename = 'vidyut_competition_' + "%s.%s" % (uuid.uuid4(), ext)
        return 'static/events/covers/' + filename

    name = models.CharField(max_length=150)
    slug = models.SlugField(unique=True)
    cover = models.ImageField(upload_to=get_image_path, null=True, blank=True)
    dept = models.ForeignKey(Department, on_delete=models.PROTECT, null=True, blank=True)
    description = models.CharField(max_length=200, null=True, blank=True)
    details = RichTextField(null=True, blank=True)
    fee = models.IntegerField(null=True, blank=True)
    firstPrize = models.CharField(max_length=150, null=True, blank=True)
    secondPrize = models.CharField(max_length=150, null=True, blank=True)
    thirdPrize = models.CharField(max_length=150, null=True, blank=True)

    def __str__(self):
        return self.name