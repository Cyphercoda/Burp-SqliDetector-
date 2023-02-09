import re
from burp import IBurpExtender
from burp import IHttpListener
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IHttpListener, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLi Scanner")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == self._callbacks.TOOL_PROXY and not messageIsRequest:
            request = messageInfo.getRequest()
            requestInfo = self._helpers.analyzeRequest(request)

            params = requestInfo.getParameters()

            for param in params:
                if re.search(r"((?i)\b(union(?:\b.*?\b)select|(?<!\\)'\b)|((?<!\\)\"))", param.getValue()):
                    issue = SQLInjectionIssue(messageInfo.getHttpService(), requestInfo.getUrl(), [self._callbacks.applyMarkers(messageInfo, None, 0, 0)], "SQL Injection", "A potential SQL injection vulnerability was detected in the following parameter: " + param.getName(), "High")
                    self._callbacks.addScanIssue(issue)

    def doPassiveScan(self, baseRequestResponse):
        pass

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getUrl() == newIssue.getUrl():
            return -1
        else:
            return 0

class SQLInjectionIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
