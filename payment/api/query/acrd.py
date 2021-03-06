import graphene
import requests
import json

from graphql_jwt.decorators import login_required

from framework.api.helper import APIException
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


class TransactionRefetchObj(graphene.ObjectType):
    successfulTransactions = graphene.List(graphene.String)
    failedTransactions = graphene.List(graphene.String)


class Query(object):
    getPaymentGatewayData = graphene.Field(PaymentLinkObj, transactionID=graphene.String())
    getOnlinePaymentStatus = graphene.Field(PaymentStatusObj, transactionID=graphene.String())
    refetchPendingStatus = graphene.Boolean()
    processOnlineTransactions = graphene.Field(TransactionRefetchObj)

    @login_required
    def resolve_refetchPendingStatus(self, info, **kwargs):
        pt = Transaction.objects.filter(isOnline=True, isProcessed=False)
        successLog = []
        failLog = []
        for t in pt:
            payload = getTransactionPayload(t.amount, t.transactionID)
            f = requests.post(ACRD_ENDPOINT + '/doubleverifythirdparty', data=payload)
            try:
                k = f.json()
                # Decrypt Response Data from ACRD, receives a JSON
                data = decryptPayload(k["data"])

                if k["response"]:
                    try:
                        jsonData = json.loads(data)
                        t.isPaid = jsonData['status'] == "SUCCESS"
                        t.isProcessed = True
                        t.manualIssue = False
                        t.transactionData = data
                        t.save()
                        if(jsonData['status'] == "SUCCESS"):
                            successLog.append(t.transactionID)
                        else:
                            failLog.append(t.transactionID)
                    except Exception as e:
                        t.isPaid = False
                        t.isProcessed = True
                        t.manualIssue = False
                        t.transactionData = data
                        failLog.append(t.transactionID)
                        t.save()
            except Exception as e:
                print(f.text)
                t.isPaid = False
                t.isProcessed = True
                t.manualIssue = False
                t.transactionData = f.text
                failLog.append(t.transactionID)
                t.save()

        return True

    @login_required
    def resolve_processOnlineTransactions(self, info, **kwargs):
        pt = Transaction.objects.filter(isOnline=True, isProcessed=False)
        successLog = []
        failLog = []
        for t in pt:
            payload = getTransactionPayload(t.amount, t.transactionID)
            f = requests.post(ACRD_ENDPOINT + '/doubleverifythirdparty', data=payload)
            try:
                k = f.json()
                # Decrypt Response Data from ACRD, receives a JSON
                data = decryptPayload(k["data"])

                if k["response"]:
                    try:
                        jsonData = json.loads(data)
                        t.isPaid = jsonData['status'] == "SUCCESS"
                        t.isProcessed = True
                        t.manualIssue = False
                        t.transactionData = data
                        t.save()
                        if (jsonData['status'] == "SUCCESS"):
                            successLog.append(t.transactionID)
                        else:
                            failLog.append(t.transactionID)
                    except Exception as e:
                        t.isPaid = False
                        t.isProcessed = True
                        t.manualIssue = False
                        t.transactionData = data
                        failLog.append(t.transactionID)
                        t.save()
            except Exception as e:
                t.isPaid = False
                t.isProcessed = True
                t.manualIssue = False
                t.transactionData = f.text
                failLog.append(t.transactionID)
                t.save()

        return TransactionRefetchObj(successfulTransactions=successLog, failedTransactions=failLog)

    @login_required
    def resolve_getPaymentGatewayData(self, info, **kwargs):
        transactionID = kwargs.get('transactionID')
        try:
            tobj = Transaction.objects.get(transactionID=transactionID)
        except Transaction.DoesNotExist:
            raise APIException("Transaction not found in the database.")
        payload = getTransactionPayload(tobj.amount, transactionID)
        return PaymentLinkObj(
            data=payload['encdata'],
            code=payload['code'],
            url=ACRD_ENDPOINT + '/makethirdpartypayment'
        )

    @login_required
    def resolve_getOnlinePaymentStatus(self, info, **kwargs):
        transactionID = kwargs.get('transactionID')
        try:
            tobj = Transaction.objects.get(transactionID=transactionID)
        except Transaction.DoesNotExist:
            raise APIException("Transaction not found in the database.")

        payload = getTransactionPayload(tobj.amount, transactionID)
        try:
            f = requests.post(ACRD_ENDPOINT + '/doubleverifythirdparty', data=payload)
            k = f.json()
        # TODO : Do better error handling
        except Exception as e:
            return PaymentStatusObj(status=False, data='Failed')

        # Decrypt Response Data from ACRD, receives a JSON
        data = decryptPayload(k["data"])

        if k["response"]:
            jsonData = json.loads(data)
            tobj.isPaid = jsonData['status'] == "SUCCESS"
            tobj.isProcessed = True
            tobj.manualIssue = False
            tobj.transactionData = data
            tobj.save()
        return PaymentStatusObj(status=k["response"], data=data)
