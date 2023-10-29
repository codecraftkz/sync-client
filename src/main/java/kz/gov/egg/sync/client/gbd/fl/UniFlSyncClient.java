package kz.gov.egg.sync.client.gbd.fl;

import java.util.Collections;
import java.util.Map;

import kz.gov.egg.sync.RequestData;
import kz.gov.egg.sync.client.AbstractSyncClient;
import kz.gov.egg.sync.client.SignConfig;
import kz.gov.egg.sync.client.utils.EggUtils;
import kz.gov.services.gbd.unifl.Request;

public final class UniFlSyncClient extends AbstractSyncClient {

    public UniFlSyncClient(String wsAddress, Map<String, String> requestParams, SignConfig signConfig) {
        super(wsAddress, requestParams, signConfig);
        wsFactory.setProperties(
                Collections.singletonMap("jaxb.additionalContextClasses", new Class[] { Request.class }));
    }

    public RequestData buildRequestData(String iin) {
        var request = new Request();
        request.setMessageId(requestParams.get("messageId"));
        request.setIin(iin);
        request.setMessageDate(EggUtils.toXmlDateTime(null));
        request.setSenderCode(requestParams.get("senderCode"));

        var requestData = new RequestData();
        requestData.setData(request);

        return requestData;
    }

}
