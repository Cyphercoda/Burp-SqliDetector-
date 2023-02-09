import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.*;

public class SQLiScanner implements IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private static final Pattern sqlInjectionRegex = Pattern.compile("(?i)((\\b(union(\\b.*?\\b)select|(?<!\\\\)')\\b)|((?<!\\\\)\"))");

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("SQLi Scanner");
        callbacks.registerHttpListener(this);
    }

    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && messageIsRequest) {
            byte[] request = messageInfo.getRequest();
            IRequestInfo requestInfo = helpers.analyzeRequest(request);

            String[] params = requestInfo.getParameters();

            for (String param : params) {
                Matcher matcher = sqlInjectionRegex.matcher(param);
                if (matcher.find()) {
                    callbacks.addScanIssue(new CustomScanIssue(messageInfo, requestInfo.getUrl(),
                            new IHttpRequestResponse[] { callbacks.applyMarkers(messageInfo, null, matcher.start(), matcher.end()) },
                            "SQL Injection", "A potential SQL injection vulnerability was detected in the following parameter: " + param,
                            "High"));
                }
            }
        }
    }

    private class CustomScanIssue implements IScanIssue {
        private IHttpRequestResponse[] httpMessages;
        private URL url;
        private IHttpService httpService;
        private String name;
        private String detail;
        private String severity;

        public CustomScanIssue(IHttpRequestResponse httpMessage, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity) {
            this.httpService = httpMessage.getHttpService();
            this.url = url;
            this.httpMessages = httpMessages;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
        }

        public URL getUrl() {
            return url;
        }

        public String getIssueName() {
            return name;
        }

        public int getIssueType() {
            return 0;
        }

        public String getSeverity() {
            return severity;
        }

        public String getConfidence() {
            return "Certain";
        }

        public String getIssueBackground() {
            return null;
        }

        public String getRemediationBackground() {
            return null;
        }

        public String getIssueDetail() {
            return detail;
        }

        public String getRemediationDetail() {
            return null;
        }

        public IHttpRequest
