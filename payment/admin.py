from django.contrib import admin
from .models import *
from easy_select2 import select2_modelform
from rangefilter.filter import DateTimeRangeFilter
from import_export import resources
from import_export.admin import ImportExportModelAdmin
from import_export.fields import Field


class TransactionResource(resources.ModelResource):
    date = Field()

    class Meta:
        model = Transaction
        fields = ('transactionID', 'isPaid', 'isProcessed', 'isPending', 'amount', 'date', 'user__username', 'issuer__username', 'timestamp', 'issuerLocation', 'issuerDevice', )

    @staticmethod
    def dehydrate_full_title(transaction):
        return transaction.timestamp.date


class OPInline(admin.TabularInline):
    model = OrderProduct
    extra = 0
    select2 = select2_modelform(OrderProduct, attrs={'width': '250px'})
    form = select2


@admin.register(Transaction)
class TransactionAdmin(ImportExportModelAdmin, admin.ModelAdmin):
    list_display = ('transactionID', 'isProcessed', 'isPending', 'isPaid', 'amount', 'user', 'issuer', 'timestamp', 'issuerLocation')
    list_select_related = (
        'user',
        'issuer'
    )
    list_filter = (
        ('timestamp', DateTimeRangeFilter),
        'isPaid',
        'isPending',
        'isProcessed',
        'amount',
    )
    date_hierarchy = 'timestamp'
    search_fields = ['user__username', 'issuer__username', 'isPaid', 'amount']
    select2 = select2_modelform(Transaction, attrs={'width': '250px'})
    form = select2
    resource_class = TransactionResource


@admin.register(Order)
class OrderAdmin(admin.ModelAdmin):
    list_display = ('orderID', 'user', 'timestamp')
    list_filter = (('timestamp', DateTimeRangeFilter),)
    autocomplete_fields = ['transaction']
    date_hierarchy = 'timestamp'
    inlines = (OPInline,)
    select2 = select2_modelform(Order, attrs={'width': '250px'})
    form = select2

