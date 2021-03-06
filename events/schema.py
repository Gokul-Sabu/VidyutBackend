import json
import graphene
from django.db.models import Count, Q

from participants.models import Profile
from registrations.models import EventRegistration
from .models import *
from pytz import timezone
from datetime import datetime, timedelta
from products.models import *

from .api.partners import Query as PartnerQueries


class DepartmentObj(graphene.ObjectType):
    name = graphene.String()
    slug = graphene.String()
    icon = graphene.String()

    def resolve_icon(self, info):
        icon = None
        if self['icon']:
            icon = info.context.build_absolute_uri(self['icon'].url)
        return icon


class ContactPersonObj(graphene.ObjectType):
    name = graphene.String()
    phone = graphene.String()
    email = graphene.String()


class KeyLabelObj(graphene.ObjectType):
    key = graphene.String()
    label = graphene.String()


class FormFieldObj(KeyLabelObj, graphene.ObjectType):
    type = graphene.String()
    options = graphene.List(KeyLabelObj)
    required = graphene.Boolean()

    def resolve_options(self, info):
        options = None
        if 'options' in self and self['options'] is not None and self['options'] is not '':
            options = self['options']
        return options

    def resolve_required(self, info):
        required = False
        if 'required' in self and self['required'] is not None and self['required'] is not '':
            required = self['required']
        return required


class BasicProductDetailsObj(graphene.ObjectType):
    productID = graphene.String()
    name = graphene.String()
    price = graphene.String()
    slots = graphene.Int()
    isAvailable = graphene.Boolean()
    requireRegistration = graphene.Boolean()
    requireAdvancePayment = graphene.Boolean()
    isAmritapurianOnly = graphene.Boolean()
    isFacultyOnly = graphene.Boolean()
    isSchoolOnly = graphene.Boolean()
    isOutsideOnly = graphene.Boolean()
    requireEventRegistration = graphene.Boolean()
    isGSTAccounted = graphene.Boolean()
    type = graphene.String()

    def resolve_productID(self, info):
        return self

    def resolve_name(self, info):
        return Product.objects.get(productID=self).name

    def resolve_isGSTAccounted(self, info):
        return Product.objects.get(productID=self).isGSTAccounted

    def resolve_price(self, info):
        product = Product.objects.get(productID=self)
        # GST Amount = Original Cost – (Original Cost * (100 / (100 + GST% ) ) )
        if product.isGSTAccounted:
            price = product.price - (product.price - (product.price * (100 / (100 + 18))))
        else:
            price = product.price
        return price

    def resolve_slots(self, info):
        return Product.objects.get(productID=self).slots

    def resolve_isFacultyOnly(self, info):
        return Product.objects.get(productID=self).isFacultyOnly

    def resolve_requireRegistration(self, info):
        return Product.objects.get(productID=self).requireRegistration

    def resolve_requireAdvancePayment(self, info):
        return Product.objects.get(productID=self).requireAdvancePayment

    def resolve_isAmritapurianOnly(self, info):
        return Product.objects.get(productID=self).isAmritapurianOnly

    def resolve_isAmritianOnly(self, info):
        return Product.objects.get(productID=self).isAmritianOnly

    def resolve_isFacultyOnly(self, info):
        return Product.objects.get(productID=self).isFacultyOnly

    def resolve_isSchoolOnly(self, info):
        return Product.objects.get(productID=self).isSchoolOnly

    def resolve_isAvailable(self, info):
        return Product.objects.get(productID=self).isAvailable

    def resolve_isOutsideOnly(self, info):
        return Product.objects.get(productID=self).isOutsideOnly

    def resolve_requireEventRegistration(self, info):
        return Product.objects.get(productID=self).requireEventRegistration


class OrganizerObj(graphene.ObjectType):
    name = graphene.String()
    id = graphene.Int()
    logo = graphene.String()

    def resolve_logo(self, info):
        url = None
        if self['logo'] is not '':
            url = info.context.build_absolute_uri(self['logo'])
        return url


class EventObj(graphene.ObjectType):
    name = graphene.String()
    slug = graphene.String()
    cover = graphene.String()
    poster = graphene.String()
    description = graphene.String()
    details = graphene.String()
    fee = graphene.Int()
    isNew = graphene.Boolean()
    isTeamEvent = graphene.Boolean()
    isPublished = graphene.Boolean()
    hasSelectionProcess = graphene.Boolean()
    minTeamSize = graphene.Int()
    maxTeamSize = graphene.Int()
    isTotalRate = graphene.Boolean()
    isRecommended = graphene.Boolean()
    department = graphene.Field(DepartmentObj)
    organizer = graphene.Field(OrganizerObj)
    contacts = graphene.List(ContactPersonObj)
    productID = graphene.String()
    products = graphene.List(BasicProductDetailsObj)
    isTrending = graphene.Boolean()

    def resolve_isTrending(self, info):
        now = datetime.now()
        regs = EventRegistration.objects.filter(
            Q(registrationTimestamp__gt=now-timedelta(days=5)) &
            (Q(event__workshop_id=self['id']) | Q(event__competition=self['id']) | Q(event__ticket_id=self['id']))
        ).count()
        return regs > 12

    def resolve_cover(self, info):
        url = None
        if self['cover'] is not '':
            url = info.context.build_absolute_uri(self['cover'])
        return url

    def resolve_poster(self, info):
        url = None
        if self['poster'] is not '':
            url = info.context.build_absolute_uri(self['poster'])
        return url

    def resolve_organizer(self, info):
        try:
            return Partners.objects.values().get(id=self['organiser_id'])
        except Partners.DoesNotExist:
            return None

    def resolve_department(self, info):
        try:
            return Department.objects.values().get(id=self['dept_id'])
        except Department.DoesNotExist:
            return None

    def resolve_isNew(self, info):
        limit = datetime.now() - timedelta(days=3)
        if self['createdAt'].replace(tzinfo=timezone('Asia/Calcutta')) > limit.replace(tzinfo=timezone('Asia/Calcutta')):
            return True
        return False


class TicketObj(EventObj, graphene.ObjectType):
    category = graphene.Field(DepartmentObj)

    def resolve_productID(self, info):
        products = Product.objects.filter(ticket_id=self['id'])
        if products.count() > 0:
            return products.first().productID

    def resolve_products(self, info):
        return Product.objects.values_list('productID', flat=True).filter(ticket_id=self['id']).order_by('name')

    def resolve_category(self, info):
        try:
            return Category.objects.values().get(id=self['category_id'])
        except Category.DoesNotExist:
            return None


class MerchandiseObj(EventObj, graphene.ObjectType):

    def resolve_productID(self, info):
        products = Product.objects.filter(merchandise_id=self['id'])
        if products.count() > 0:
            return products.first().productID

    def resolve_products(self, info):
        return Product.objects.values_list('productID', flat=True).filter(merchandise_id=self['id']).order_by('name')


class TrainerProfileObj(graphene.ObjectType):
    name = graphene.String()
    about = graphene.String()
    photo = graphene.String()

    def resolve_photo(self, info):
        url = None
        if self['photo'] is not '':
            url = info.context.build_absolute_uri(self['photo'])
        return url


class VenueObj(graphene.ObjectType):
    name = graphene.String()
    address = graphene.String()


class SlotObj(graphene.ObjectType):
    startTime = graphene.String()
    endTime = graphene.String()
    id = graphene.Int()


class DailyScheduleObj(graphene.ObjectType):
    slot = graphene.Field(SlotObj)
    venue = graphene.Field(VenueObj)

    def resolve_slot(self, info):
        return TimeSlot.objects.values().get(id=self['slot_id'])

    def resolve_venue(self, info):
        if self['venue_id'] is not None:
            return Venue.objects.values().get(id=self['venue_id'])
        else:
            return None


class PartnerObj(graphene.ObjectType):
    name = graphene.String()
    logo = graphene.String()

    def resolve_logo(self, info):
        url = None
        if self['logo'] and self['logo'] is not '':
            url = info.context.build_absolute_uri(self['logo'])
        return url


class WorkshopObj(EventObj, graphene.ObjectType):
    syllabus = graphene.String()
    eligibility = graphene.String()
    mediumOfInstruction = graphene.String()
    certificate = graphene.String()
    trainers = graphene.List(TrainerProfileObj)
    schedule = graphene.List(DailyScheduleObj)
    accreditedBy = graphene.Field(PartnerObj)
    partners = graphene.List(PartnerObj)
    KTUActivityPoints = graphene.Int()

    def resolve_accreditedBy(self, info):
        if Workshop.objects.get(slug=self['slug']).accreditedBy is not None:
            acc = Workshop.objects.get(slug=self['slug']).accreditedBy
            logo = None
            if acc.logo and hasattr(acc.logo, 'url'):
                logo = info.context.build_absolute_uri(acc.logo.url)
            return {
                'name': acc.name,
                'logo': logo
            }
        return None

    def resolve_partners(self, info):
        if Workshop.objects.get(slug=self['slug']).partners is not None:
            partners = Workshop.objects.get(slug=self['slug']).partners.all()
            return Partners.objects.values().filter(id__in=partners).order_by('name')
        return None

    def resolve_trainers(self, info):
        return Workshop.objects.get(slug=self['slug']).trainers.values().all()

    def resolve_schedule(self, info):
        return WorkshopSchedule.objects.values().filter(event__slug=self['slug'])

    def resolve_contacts(self, info):
        contacts = Workshop.objects.get(slug=self['slug']).contacts
        return contacts.values()

    def resolve_productID(self, info):
        products = Product.objects.filter(workshop_id=self['id'])
        if products.count() > 0:
            return products.first().productID

    def resolve_products(self, info):
        return Product.objects.values_list('productID', flat=True).filter(workshop_id=self['id']).order_by('name')


class CompetitionObj(EventObj, graphene.ObjectType):
    entryFee = graphene.Int()
    totalPrize = graphene.String()
    firstPrize = graphene.String()
    secondPrize = graphene.String()
    thirdPrize = graphene.String()
    otherPrizes = graphene.String()
    judgingCriteria = graphene.String()
    rules = graphene.String()
    formFields = graphene.List(FormFieldObj)
    schedule = graphene.List(DailyScheduleObj)
    category = graphene.Field(DepartmentObj)
    KTUActivityPoints = graphene.Int()

    def resolve_schedule(self, info):
        return CompetitionSchedule.objects.values().filter(event__slug=self['slug'])

    def resolve_contacts(self, info):
        contacts = Competition.objects.get(slug=self['slug']).contacts
        return contacts.values()

    def resolve_productID(self, info):
        products = Product.objects.filter(competition_id=self['id'])
        if products.count() > 0:
            return products.first().productID

    def resolve_products(self, info):
        return Product.objects.values_list('productID', flat=True).filter(competition_id=self['id']).order_by('name')

    def resolve_formFields(self, info):
        if self['formFields'] is not '' and self['formFields'] is not None:
            return json.loads(self['formFields'])
        return None

    def resolve_category(self, info):
        try:
            return Category.objects.values().get(id=self['category_id'])
        except Category.DoesNotExist:
            return None


class DepartmentListObj(graphene.ObjectType):
    name = graphene.String()
    slug = graphene.String()
    icon = graphene.String()

    def resolve_icon(self, info):
        url = None
        if self['icon']:
            url = info.context.build_absolute_uri(self['icon'])
        return url


class CategoryObj(graphene.ObjectType):
    name = graphene.String()
    slug = graphene.String() #slug
    competitions = graphene.List(CompetitionObj)
    ticketEvents = graphene.List(TicketObj)

    def resolve_competitions(self, info):
        return Competition.objects.values().filter(category=self).distinct().order_by('-isRecommended', 'dept__name', 'name')

    def resolve_ticketEvents(self, info):
        return Ticket.objects.values().filter(category=self).distinct().order_by('-isRecommended', 'name')


class CategoryListObj(graphene.ObjectType):
    name = graphene.String()
    slug = graphene.String()


class Query(PartnerQueries, object):
    getCompetition = graphene.Field(CompetitionObj, slug=graphene.String(required=True))
    getWorkshop = graphene.Field(WorkshopObj, slug=graphene.String(required=True))
    getTicketEvent = graphene.Field(TicketObj, slug=graphene.String(required=True))
    getMerchandise = graphene.Field(MerchandiseObj, slug=graphene.String(required=True))
    listDepartments = graphene.List(DepartmentListObj)
    listCategories = graphene.List(CategoryListObj)
    listOrganizers = graphene.List(OrganizerObj, hasWorkshop=graphene.Boolean(required=False))
    listCompetitions = graphene.List(CompetitionObj)
    listWorkshops = graphene.List(WorkshopObj)
    listMerchandise = graphene.List(MerchandiseObj)
    listTicketEvents = graphene.List(TicketObj)
    listTeamCompetitions = graphene.List(CompetitionObj)
    listByCategory = graphene.List(CategoryObj)
    listRecommendedCompetitions = graphene.List(CompetitionObj)

    @staticmethod
    def resolve_listRecommendedCompetitions(self, info, **kwargs):
        return Competition.objects.values().filter(isRecommended=True).distinct().order_by('dept__name', 'name')

    @staticmethod
    def resolve_listByCategory(self, info, **kwargs):
        return Category.objects.all().order_by('listingWeight')

    @staticmethod
    def resolve_listDepartments(self, info, **kwargs):
        return Department.objects.values().all().order_by('name')

    @staticmethod
    def resolve_listCategories(self, info, **kwargs):
        return Category.objects.values().all().order_by('name')

    @staticmethod
    def resolve_listOrganizers(self, info, **kwargs):
        hasWorkshop = kwargs.get('hasWorkshop')
        if hasWorkshop is None:
            return Partners.objects.values().all().order_by('name')
        else:
            list = Workshop.objects.all().values_list('organiser', flat=True)
            return Partners.objects.values().filter(id__in=list).order_by('name')

    @staticmethod
    def resolve_getCompetition(self, info, **kwargs):
        slug = kwargs.get('slug')
        return Competition.objects.values().get(slug=slug)

    @staticmethod
    def resolve_listCompetitions(self, info, **kwargs):
        user = info.context.user
        if user.id:
            profile = Profile.objects.get(user=user)
            if profile.isSchoolStudent:
                return Competition.objects.values().filter(
                    isPublished=True,
                    product__isSchoolOnly=True
                ).distinct().order_by('-isRecommended', 'dept__name', 'name')
            elif profile.isFaculty:
                return Competition.objects.values().filter(
                    isPublished=True,
                    product__isFacultyOnly=True
                ).distinct().order_by('-isRecommended', 'dept__name', 'name')
            return Competition.objects.values().filter(
                isPublished=True,
                product__isSchoolOnly=False,
                product__isFacultyOnly=False
            ).distinct().order_by('-isRecommended', 'dept__name', 'name')
        else:
            return Competition.objects.values().filter(isPublished=True).order_by('-isRecommended', 'dept__name', 'name')

    @staticmethod
    def resolve_listTeamCompetitions(self, info, **kwargs):
        return Competition.objects.values().filter(isTeamEvent=True, isPublished=True).order_by('name')

    @staticmethod
    def resolve_getWorkshop(self, info, **kwargs):
        slug = kwargs.get('slug')
        return Workshop.objects.values().get(slug=slug)

    @staticmethod
    def resolve_listWorkshops(self, info, **kwargs):
        user = info.context.user
        if user.id:
            profile = Profile.objects.get(user=user)
            if profile.isSchoolStudent:
                return Workshop.objects.values().filter(
                    isPublished=True,
                    product__isSchoolOnly=True
                ).distinct().order_by('-isRecommended', 'accreditedBy__name', 'organiser', 'dept__name', 'name')
            elif profile.isFaculty:
                return Workshop.objects.values().filter(
                    isPublished=True,
                    product__isFacultyOnly=True
                ).distinct().order_by('-isRecommended', 'accreditedBy__name', 'organiser', 'dept__name', 'name')
            return Workshop.objects.values().filter(
                isPublished=True,
                product__isSchoolOnly=False,
                product__isFacultyOnly=False
            ).distinct().order_by('-isRecommended', 'accreditedBy__name', 'organiser', 'dept__name', 'name')
        else:
            return Workshop.objects.values().filter(isPublished=True).order_by('-isRecommended', 'dept__name', 'name')

    @staticmethod
    def resolve_getMerchandise(self, info, **kwargs):
        slug = kwargs.get('slug')
        return Merchandise.objects.values().get(slug=slug)

    @staticmethod
    def resolve_listMerchandise(self, info, **kwargs):
        return Merchandise.objects.values().filter(isPublished=True).order_by('name')

    @staticmethod
    def resolve_getTicketEvent(self, info, **kwargs):
        slug = kwargs.get('slug')
        return Ticket.objects.values().get(slug=slug)

    @staticmethod
    def resolve_listTicketEvents(self, info, **kwargs):
        return Ticket.objects.values().filter(isPublished=True).order_by('-isRecommended', 'name')
