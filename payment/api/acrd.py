import graphene
import requests
import json

from graphql_jwt.decorators import login_required

from payment.acrd.helper import getTransactionPayload, decryptPayload
from framework.settings import ACRD_ENDPOINT

from payment.models import Transaction


class PaymentLinkObj(graphene.ObjectType):
    url = graphene.String()
    data = graphene.String()
    code = graphene.String()


class PaymentStatusObj(graphene.ObjectType):
    status = graphene.Boolean()
    data = graphene.JSONString()


class Query(object):
    getPaymentGatewayData = graphene.Field(PaymentLinkObj, transactionID=graphene.String())
    getOnlinePaymentStatus = graphene.Field(PaymentStatusObj, transactionID=graphene.String())

    @login_required
    def resolve_getPaymentGatewayData(self, info, **kwargs):
        transactionID = kwargs.get('transactionID')
        try:
            tobj = Transaction.objects.get(transactionID=transactionID)
        except Transaction.DoesNotExist:
            return None
        payload = getTransactionPayload(tobj.amount, transactionID)
        return PaymentLinkObj(
            data=payload['encdata'],
            code=payload['code'],
            url=ACRD_ENDPOINT + '/makethirdpartypayment'
        )


    @login_required
    def resolve_getOnlinePaymentStatus(self, info, **kwargs):
        transactionID = kwargs.get('transactionID')

        # TODO better error handling
        try:
            tobj = Transaction.objects.get(transactionID=transactionID)
        except Transaction.DoesNotExist:
            return None

        payload = getTransactionPayload(tobj.amount, transactionID)
        try:
            f = requests.post(ACRD_ENDPOINT + '/doubleverifythirdparty', data=payload)
        except Exception as e:
            return PaymentStatusObj(status=False, data='Failed')
        j = f.text
        k = json.loads(j)

        # Decrypt Response Data from ACRD, receives a JSON
        data = decryptPayload(k["data"])

        if k["response"]:
            jsonData = json.load(data)
            tobj.isPaid = jsonData.status == "SUCCESS"
            tobj.isProcessed = True
            tobj.manualIssue = False
            tobj.transactionData = data
            tobj.save()
        return PaymentStatusObj(status=k["response"], data=data)

