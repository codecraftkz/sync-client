package kz.gov.egg.sync.client.gbd.ul;

import java.util.Collections;
import java.util.Map;

import kz.gov.egg.sync.RequestData;
import kz.gov.egg.sync.client.AbstractSyncClient;
import kz.gov.egg.sync.client.SignConfig;
import kz.gov.egg.sync.client.utils.EggUtils;
import kz.gov.services.gbd.binul.Request;

public final class BinUlSyncClient extends AbstractSyncClient {

    public BinUlSyncClient(String wsAddress, Map<String, String> requestParams, SignConfig signConfig) {
        super(wsAddress, requestParams, signConfig);
        wsFactory.setProperties(
                Collections.singletonMap("jaxb.additionalContextClasses", new Class[] { Request.class }));

    }

    public RequestData buildRequestData(String bin) {
        var request = new Request();
        request.setRequestorBIN(requestParams.get("RequestorBIN"));
        request.setBIN(bin);
        var xml = EggUtils.marshal("http://gbdulinfobybin_v2.egp.gbdul.tamur.kz", request, Request.class);
        var signedXml = envelopedSigner.sign(xml);

        var requestData = new RequestData();
        requestData.setData(signedXml);

        return requestData;
    }

}
