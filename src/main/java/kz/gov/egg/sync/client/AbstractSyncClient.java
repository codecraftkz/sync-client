package kz.gov.egg.sync.client;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import org.apache.cxf.binding.soap.saaj.SAAJInInterceptor;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxws.JaxWsProxyFactoryBean;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.w3c.dom.Node;

import kz.gov.egg.sync.ISyncChannel;
import kz.gov.egg.sync.RequestData;
import kz.gov.egg.sync.SendMessageSendMessageFaultMsg;
import kz.gov.egg.sync.SenderInfo;
import kz.gov.egg.sync.SyncMessageInfo;
import kz.gov.egg.sync.SyncSendMessageRequest;
import kz.gov.egg.sync.SyncSendMessageResponse;
import kz.gov.egg.sync.client.soap.InInterceptor;
import kz.gov.egg.sync.client.utils.EggUtils;
import kz.gov.egg.sync.client.utils.EnvelopedSigner;

public abstract class AbstractSyncClient implements EggSyncClient {

    protected JaxWsProxyFactoryBean wsFactory;
    protected ISyncChannel syncChannel;
    protected SignConfig signConfig;
    protected EnvelopedSigner envelopedSigner;
    protected Map<String, String> requestParams;

    protected AbstractSyncClient(String wsAddress, Map<String, String> requestParams, SignConfig signConfig) {
        wsFactory = new JaxWsProxyFactoryBean();
        wsFactory.setServiceClass(ISyncChannel.class);
        wsFactory.setAddress(wsAddress);
        WSS4JOutInterceptor outInterceptor = new WSS4JOutInterceptor(signConfig.getOutInterceptorProperties());
        wsFactory.setOutInterceptors(Arrays.asList(outInterceptor));
        // TODO: Add WSS4JInInterceptor
        wsFactory.setInInterceptors(Arrays.asList(new SAAJInInterceptor(), new InInterceptor(signConfig)));
        this.requestParams = Collections.unmodifiableMap(requestParams);
        this.signConfig = signConfig;
        envelopedSigner = new EnvelopedSigner(signConfig);
    }

    public final void setLoggingFeature(LoggingFeature loggingFeature) {
        if (loggingFeature != null) {
            wsFactory.getFeatures().add(loggingFeature);
        }
    }

    public final void init() {
        syncChannel = (ISyncChannel) wsFactory.create();
    }

    protected final SyncSendMessageResponse sendMessage(SyncSendMessageRequest messageRequest) {
        try {
            return syncChannel.sendMessage(messageRequest);
        } catch (SendMessageSendMessageFaultMsg e) {
            throw new RuntimeException(e);
        }
    }

    protected final SyncSendMessageRequest buildMessageRequest(RequestData requestData) {
        var senderInfo = new SenderInfo();
        senderInfo.setSenderId(requestParams.get("senderId"));
        senderInfo.setPassword(requestParams.get("password"));

        var requestInfo = new SyncMessageInfo();
        requestInfo.setMessageId(requestParams.get("messageId"));
        requestInfo.setMessageDate(EggUtils.toXmlDateTime(null));
        requestInfo.setServiceId(requestParams.get("serviceId"));
        requestInfo.setSender(senderInfo);

        SyncSendMessageRequest messageRequest = new SyncSendMessageRequest();
        messageRequest.setRequestData(requestData);
        messageRequest.setRequestInfo(requestInfo);

        return messageRequest;
    }

    public String fetchResponseData(RequestData requestData) {
        var messageRequest = buildMessageRequest(requestData);
        var messageResponse = sendMessage(messageRequest);
        var data = messageResponse.getResponseData().getData();
        return EggUtils.nodeToString((Node) data);
    }

}
