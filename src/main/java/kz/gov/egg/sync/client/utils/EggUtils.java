package kz.gov.egg.sync.client.utils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import javax.xml.XMLConstants;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.w3c.dom.Node;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import lombok.experimental.UtilityClass;

@UtilityClass
public class EggUtils {

    public static XMLGregorianCalendar toXmlDateTime(LocalDateTime dateTime) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'+06:00'");
        String xmlDateTime;
        if (dateTime == null) {
            xmlDateTime = formatter.format(LocalDateTime.now());
        } else {
            xmlDateTime = formatter.format(dateTime);
        }
        try {
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(xmlDateTime);
        } catch (DatatypeConfigurationException e) {
            throw new IllegalArgumentException("Failed to parse as XML datetime.");
        }
    }

    public static String marshal(Class c, Object o, String qname) {
        try (StringWriter sw = new StringWriter()) {
            JAXBContext ctx = JAXBContext.newInstance(c);
            Marshaller marshaller = ctx.createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            JAXBElement<Object> el = new JAXBElement<Object>(new QName(qname, c.getSimpleName()), c, o);
            marshaller.marshal(el, sw);
            return sw.toString();
        } catch (IOException | JAXBException e) {
            throw new IllegalStateException(o.getClass() + " marshalling failed.");
        }
    }

    public static <T> T unmarshal(Class<T> c, String xml) {
        try {
            JAXBContext ctx = JAXBContext.newInstance(c);
            Unmarshaller unmarshaller = ctx.createUnmarshaller();
            JAXBElement<T> element = unmarshaller.unmarshal(new StreamSource(new StringReader(xml)), c);
            return element.getValue();
        } catch (JAXBException e) {
            throw new IllegalStateException("Unmarshalling failed for " + c);
        }
    }

    public static String nodeToString(Node node) {
        try (var sw = new StringWriter()) {
            var source = new DOMSource(node);
            var result = new StreamResult(sw);

            TransformerFactory transFactory = TransformerFactory.newInstance();
            transFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            try {
                transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
                transFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            } catch (IllegalArgumentException ex) {
                // ignore
            }

            Transformer transformer = transFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            transformer.transform(source, result);
            return sw.toString();
        } catch (TransformerException | IOException e) {
            throw new IllegalStateException("Node not transformed.", e);
        }
    }
}
