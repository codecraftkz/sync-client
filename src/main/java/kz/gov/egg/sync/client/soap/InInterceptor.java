package kz.gov.egg.sync.client.soap;

import org.apache.cxf.binding.soap.SoapMessage;
import org.apache.cxf.binding.soap.interceptor.AbstractSoapInterceptor;
import org.apache.cxf.binding.xml.XMLFault;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.phase.Phase;
import org.apache.wss4j.common.util.XMLUtils;

import jakarta.xml.soap.SOAPException;
import jakarta.xml.soap.SOAPMessage;
import kz.gov.egg.sync.client.SignConfig;
import kz.gov.egg.sync.client.utils.EggUtils;
import kz.gov.egg.sync.client.utils.EnvelopedSigner;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class InInterceptor extends AbstractSoapInterceptor {

    private EnvelopedSigner envelopedSigner;

    public InInterceptor(SignConfig signConfig) {
        super(Phase.POST_PROTOCOL);
        addAfter("org.apache.cxf.binding.soap.saaj.SAAJInInterceptor");
        envelopedSigner = new EnvelopedSigner(signConfig);
    }

    @Override
    public void handleMessage(SoapMessage message) throws Fault {
        var msg = message.getContent(SOAPMessage.class);
        try {
            var envelope = msg.getSOAPBody().getFirstChild();
            var node = XMLUtils.findElement(envelope, "data", null);
            if (node == null) {
                throw new XMLFault("<data> not found.");
            }
            var type = node.getAttribute("xsi:type");
            String dataXml;
            if ("xs:string".equals(type)) {
                var nodes = node.getChildNodes();
                var textBuilder = new StringBuilder();
                for (int i = 0; i < nodes.getLength(); i++) {
                    textBuilder.append(nodes.item(i).getTextContent());
                }
                dataXml = textBuilder.toString();
            } else {
                dataXml = EggUtils.nodeToString(node);
            }
            log.debug("Essential data:\n{}", dataXml);

            if (!envelopedSigner.verify(dataXml)) {
                throw new XMLFault("<data> has invalid signature.");
            }
            log.debug("<data> verified.");
        } catch (SOAPException e) {
            throw new XMLFault("InInterceptor handling failed.");
        }
    }

}
